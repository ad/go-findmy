import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import anisette_sidecar


class FakeMachine:
    built = 0

    def __init__(self, state):
        FakeMachine.built += 1
        self.state = state
        state.mkdir(parents=True, exist_ok=True)
        self.calls = 0
        self.fail = None
        self.mid = "mid"

    def provision(self):
        (self.state / "identity.json").write_text("{}")
        return {"routing": 17106176}

    def headers(self):
        if self.fail:
            raise self.fail
        self.calls += 1
        return {"X-Apple-I-MD": f"otp{self.calls}", "X-Apple-I-MD-M": self.mid}


class FakeResyncer:
    result = "revived"
    built = 0

    def __init__(self, state):
        FakeResyncer.built += 1
        self.machine = FakeMachine(state)
        self.machine.mid = "resynced"

    async def ensure_fresh(self):
        return FakeResyncer.result


class SidecarTest(unittest.TestCase):
    def setUp(self):
        FakeMachine.built = 0
        FakeResyncer.built = 0
        FakeResyncer.result = "revived"
        self.state = Path(tempfile.mkdtemp())
        self.sidecar = anisette_sidecar.Sidecar(self.state, FakeMachine, FakeResyncer)
        self.server = anisette_sidecar.serve(self.sidecar, 0)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, method, path):
        url = f"http://127.0.0.1:{self.server.server_port}{path}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url, method=method)) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as err:
            with err:
                return err.code, json.load(err)

    def provision(self):
        (self.state / "identity.json").write_text("{}")

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_health_reports_unprovisioned_state(self):
        self.assertEqual(self.call("GET", "/health"), (200, {"ok": True, "provisioned": False}))

    def test_headers_on_empty_state_refuses_and_never_builds_machine(self):
        status, body = self.call("GET", "/headers")
        self.assertEqual(status, 503)
        self.assertIn("not provisioned", body["error"])
        self.assertEqual(FakeMachine.built, 0)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_headers_are_fresh_per_call_from_one_machine(self):
        self.provision()
        self.assertEqual(self.call("GET", "/headers"), (200, {"X-Apple-I-MD": "otp1", "X-Apple-I-MD-M": "mid"}))
        self.assertEqual(self.call("GET", "/headers")[1]["X-Apple-I-MD"], "otp2")
        self.assertEqual(FakeMachine.built, 1)

    def test_coreadi_system_exit_is_an_error_reply_not_a_dead_sidecar(self):
        self.provision()
        self.call("GET", "/headers")
        self.sidecar._machine.fail = SystemExit("RequestOTP failed: -45054")
        status, body = self.call("GET", "/headers")
        self.assertEqual(status, 500)
        self.assertIn("-45054", body["error"])
        self.assertEqual(self.call("GET", "/health")[0], 200)

    def test_resync_on_empty_state_refuses(self):
        self.assertEqual(self.call("POST", "/resync")[0], 503)
        self.assertEqual(FakeResyncer.built, 0)

    def test_headers_after_resync_come_from_the_resynced_machine(self):
        self.provision()
        self.call("GET", "/headers")
        self.assertEqual(self.call("POST", "/resync"), (200, {"result": "revived"}))
        self.assertEqual(self.call("GET", "/headers")[1]["X-Apple-I-MD-M"], "resynced")

    def test_resync_that_did_not_revive_is_an_error(self):
        self.provision()
        FakeResyncer.result = "refused"
        self.assertEqual(self.call("POST", "/resync"), (502, {"result": "refused"}))


class ProvisionTest(unittest.TestCase):
    def setUp(self):
        FakeMachine.built = 0
        self.state = Path(tempfile.mkdtemp()) / "anisette"

    def test_provisions_a_missing_state_dir(self):
        anisette_sidecar.provision(self.state, FakeMachine)
        self.assertTrue((self.state / "identity.json").exists())

    def test_never_touches_a_non_empty_state_dir(self):
        self.state.mkdir()
        (self.state / "store").mkdir()
        with self.assertRaises(SystemExit):
            anisette_sidecar.provision(self.state, FakeMachine)
        self.assertEqual(FakeMachine.built, 0)


if __name__ == "__main__":
    unittest.main()
