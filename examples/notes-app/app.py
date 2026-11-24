#!/usr/bin/env python3
"""A small, well-behaved example app used by the SecureAIWarp end-to-end tests.

    python3 app.py count          count the notes in the picked folder and store
                                  the result in APP_DATA/count.json (offline)
    python3 app.py summarize      read every note in the picked folder, ask the
                                  summary API (needs NOTES_API_KEY) and store
                                  the result in APP_DATA/summary.json
    python3 app.py serve [--once] serve the stored summary on 127.0.0.1:8080

It only uses what its warp.yaml declares: the picked "notes" folder (read
only), its own APP_DATA, api.notes.example:443 with NOTES_API_KEY in the
x-api-key header, and an HTTP UI on port 8080.
"""
import http.server
import json
import os
import sys
import urllib.request

API = os.environ.get("NOTES_API", "https://api.notes.example/v1/summarize")


def notes_dir():
    d = os.environ.get("WARP_PICK_NOTES")
    if not d:
        sys.exit("WARP_PICK_NOTES is not set (pick the notes folder)")
    return d


def read_notes():
    d = notes_dir()
    texts = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name)
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                texts.append(f.read())
    return texts


def data_path(name):
    return os.path.join(os.environ.get("APP_DATA", "/nonexistent"), name)


def count():
    texts = read_notes()
    with open(data_path("count.json"), "w", encoding="utf-8") as f:
        json.dump({"notes": len(texts)}, f)
    print("notes:", len(texts))


def summarize():
    texts = read_notes()
    body = json.dumps({"notes": len(texts), "chars": sum(len(t) for t in texts)}).encode()
    req = urllib.request.Request(API, data=body, method="POST", headers={
        "content-type": "application/json",
        "x-api-key": os.environ.get("NOTES_API_KEY", ""),
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        result = json.load(resp)
    with open(data_path("summary.json"), "w", encoding="utf-8") as f:
        json.dump(result, f)
    print("summary ok:", result.get("summary"))


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        data = ""
        for name in ("summary.json", "count.json"):
            try:
                with open(data_path(name), encoding="utf-8") as f:
                    data += f.read() + "\n"
            except OSError:
                pass
        payload = ("<html><body><h1>notes</h1><pre>%s</pre></body></html>" % data).encode()
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def serve(once):
    srv = http.server.HTTPServer(("127.0.0.1", 8080), Handler)
    print("serving on 127.0.0.1:8080", flush=True)
    if once:
        srv.handle_request()
    else:
        srv.serve_forever()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "summarize"
    if cmd == "count":
        count()
    elif cmd == "summarize":
        summarize()
    elif cmd == "serve":
        serve("--once" in sys.argv)
    else:
        sys.exit("unknown command " + cmd)
