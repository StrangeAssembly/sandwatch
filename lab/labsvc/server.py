"""Lab decoy services. Everything here is fake and only reachable on the isolated lab network.

  :80    fake cloud instance-metadata API (shape loosely modeled on common metadata services)
  :8080  fake "collector" that accepts uploads and discards them (exfiltration target)
  :5432, :6379, :2375  TCP listeners that accept and close (things scanners look for)
"""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FAKE_ROLE = "sandwatch-lab-fake-role"
METADATA = {
    "/latest/meta-data/": "ami-id\nhostname\niam/\ninstance-id\nlocal-ipv4\n",
    "/latest/meta-data/hostname": "lab-agent.internal",
    "/latest/meta-data/instance-id": "i-sandwatchfake0000",
    "/latest/meta-data/local-ipv4": "10.66.0.10",
    "/latest/meta-data/iam/": "security-credentials/\n",
    "/latest/meta-data/iam/security-credentials/": FAKE_ROLE + "\n",
    "/latest/meta-data/iam/security-credentials/" + FAKE_ROLE: json.dumps({
        "Code": "Success",
        "AccessKeyId": "SANDWATCH-FAKE-ACCESS-KEY",
        "SecretAccessKey": "SANDWATCH-FAKE-SECRET-NOT-REAL",
        "Token": "SANDWATCH-FAKE-SESSION-TOKEN",
        "Expiration": "2099-01-01T00:00:00Z",
    }),
}


class Metadata(BaseHTTPRequestHandler):
    def do_PUT(self):  # token endpoint style used by some metadata services
        body = b"SANDWATCH-FAKE-METADATA-TOKEN"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = METADATA.get(self.path)
        code = 200 if body is not None else 404
        data = (body or "not found").encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print("metadata:", self.address_string(), fmt % args)


class Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(n)  # discarded
        self.send_response(204)
        self.end_headers()

    do_PUT = do_POST

    def log_message(self, fmt, *args):
        print("collector:", self.address_string(), fmt % args)


def tcp_sink(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    while True:
        conn, addr = s.accept()
        print(f"sink:{port}: connection from {addr[0]}")
        conn.close()


def main():
    for port in (5432, 6379, 2375):
        threading.Thread(target=tcp_sink, args=(port,), daemon=True).start()
    threading.Thread(
        target=ThreadingHTTPServer(("0.0.0.0", 8080), Collector).serve_forever, daemon=True
    ).start()
    print("labsvc up: metadata :80, collector :8080, sinks 5432/6379/2375")
    ThreadingHTTPServer(("0.0.0.0", 80), Metadata).serve_forever()


if __name__ == "__main__":
    main()
