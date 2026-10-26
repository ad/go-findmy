import argparse
import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def provision(state, new_machine):
    state = Path(state)
    if state.exists() and any(state.iterdir()):
        raise SystemExit(f"{state} is not empty; refusing to provision over an existing machine")
    return new_machine(state).provision()


class NotProvisioned(Exception):
    pass


class Sidecar:
    def __init__(self, state, new_machine, new_resyncer):
        self.state = Path(state)
        self._new_machine = new_machine
        self._new_resyncer = new_resyncer
        self._machine = None
        self._lock = threading.Lock()

    def provisioned(self):
        return (self.state / "identity.json").exists()

    def headers(self):
        with self._lock:
            if self._machine is None:
                if not self.provisioned():
                    raise NotProvisioned(f"{self.state} is not provisioned")
                self._machine = self._new_machine(self.state)
            return self._machine.headers()

    def resync(self):
        with self._lock:
            if not self.provisioned():
                raise NotProvisioned(f"{self.state} is not provisioned")
            resyncer = self._new_resyncer(self.state)
            # Resyncer loads its own copy of the store and saves it after sync; the old copy
            # would overwrite the synced store on its next OTP.
            self._machine = resyncer.machine
            return asyncio.run(resyncer.ensure_fresh())

    def provision(self):
        with self._lock:
            if self.provisioned():
                return "exists"
            provision(self.state, self._new_machine)
            self._machine = None
            return "provisioned"


def serve(sidecar, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.reply(200, {"ok": True, "provisioned": sidecar.provisioned()})
            elif self.path == "/headers":
                self.run(lambda: (200, sidecar.headers()))
            else:
                self.reply(404, {"error": "not found"})

        def do_POST(self):
            if self.path == "/resync":
                self.run(self.resync)
            elif self.path == "/provision":
                self.run(lambda: (200, {"result": sidecar.provision()}))
            else:
                self.reply(404, {"error": "not found"})

        def resync(self):
            result = sidecar.resync()
            return (200 if result in ("accepted", "revived") else 502), {"result": result}

        def run(self, op):
            try:
                status, body = op()
            except NotProvisioned as err:
                status, body = 503, {"error": str(err)}
            except (Exception, SystemExit) as err:
                status, body = 500, {"error": str(err)}
            self.reply(status, body)

        def reply(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    ap = argparse.ArgumentParser(description="HTTP shim over os-findmy-e MacAnisette")
    ap.add_argument("command", choices=["serve", "provision"])
    ap.add_argument("--state", required=True, help="machine state directory")
    ap.add_argument("--osfe", required=True, help="os-findmy-e checkout")
    ap.add_argument("--port", type=int, default=6969)
    args = ap.parse_args()

    sys.path.insert(0, str(Path(args.osfe) / "tools" / "machoadi"))
    from mac_anisette import MacAnisette
    from resync import Resyncer

    if args.command == "provision":
        print(json.dumps(provision(args.state, MacAnisette)))
        return
    serve(Sidecar(args.state, MacAnisette, Resyncer), args.port).serve_forever()


if __name__ == "__main__":
    main()
