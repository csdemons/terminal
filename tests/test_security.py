"""Regression tests for AD connection handling and node trust boundaries.

Run: python3 -m unittest discover -s tests -p 'test_security.py' -v
LDAP transport is modelled here; a real AD/X2Go pilot is still required.
"""
import copy
import importlib.machinery
import importlib.util
import io
import subprocess
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parent.parent


def load_module(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


broker = load_module("security_broker", ROOT / "broker/rrcki_x2gobroker.py")
agent = load_module("security_agent", ROOT / "node/x2go-node-agent")


def session(sid="sid1", user="ivanov"):
    return "|".join(["1000", sid, "50", "term", "R", "2026-11-16T09:00:00",
                     "cookie", "192.0.2.1", "30001", "30002",
                     "2026-11-16T10:00:00", user])


def status():
    return {"ok": True, "sessions": [], "mem_total": 100, "mem_avail": 90,
            "cpus": 4, "load1": 0.1, "load5": 0.2}


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cfg = broker.load_config(ROOT / "etc/broker.toml.example")
        self.cfg["broker"].update(state_file=self.tmp.name + "/state.json", offline_after=1)
        self.audit = broker.Audit(self.tmp.name + "/audit.jsonl")
        self.farm = broker.Farm(self.cfg, self.audit)
        self.addCleanup(self.farm.pool.shutdown, wait=True)
        for node in self.farm.nodes.values():
            node.online = node.ever_seen = True
            node.status = status()

    def ldap_connection(self, conn):
        cfg = copy.deepcopy(self.cfg["auth"])
        cfg["backend"] = "static"
        auth = broker.Authenticator(cfg, self.audit, self.cfg["pools"])
        fake = types.ModuleType("ldap3")
        fake.Tls = Mock()
        fake.Server = Mock()
        fake.ServerPool = Mock()
        fake.FIRST, fake.NONE, fake.SIMPLE = "FIRST", "NONE", "SIMPLE"
        fake.Connection = Mock(return_value=conn)
        conv = types.ModuleType("ldap3.utils.conv")
        conv.escape_filter_chars = lambda value: value
        return auth, {"ldap3": fake, "ldap3.utils.conv": conv}

    def test_successful_ldap_open_returns_none(self):
        conn = Mock(closed=False, result={"result": 0}, entries=[object()])
        conn.open.return_value = None  # real SYNC strategy semantics
        conn.server.ssl = True
        conn.bind.return_value = True
        auth, modules = self.ldap_connection(conn)
        with patch.dict(sys.modules, modules):
            roles = auth._check_ldap("ivanov", "secret")
        self.assertIn("admin", roles)
        self.assertIn("pool:desktop", roles)
        conn.bind.assert_called_once()
        conn.unbind.assert_called_once()

    def test_ldap_closed_connection_fails(self):
        conn = Mock(closed=True, result={})
        auth, modules = self.ldap_connection(conn)
        with patch.dict(sys.modules, modules), self.assertRaises(RuntimeError):
            auth._check_ldap("ivanov", "secret")
        conn.bind.assert_not_called()
        conn.unbind.assert_called_once()

    def test_starttls_failure_does_not_send_password(self):
        conn = Mock(closed=False, result={})
        conn.server.ssl = False
        conn.start_tls.return_value = False
        auth, modules = self.ldap_connection(conn)
        with patch.dict(sys.modules, modules), self.assertRaises(RuntimeError):
            auth._check_ldap("ivanov", "secret")
        conn.bind.assert_not_called()

    def test_directory_search_error_does_not_grant_role(self):
        conn = Mock(closed=False, result={"result": 50}, entries=[object()])
        conn.server.ssl = True
        conn.bind.return_value = True
        auth, modules = self.ldap_connection(conn)
        with patch.dict(sys.modules, modules), self.assertRaises(RuntimeError):
            auth._check_ldap("ivanov", "secret")

    def test_malformed_node_does_not_abort_other_nodes(self):
        nodes = list(self.farm.nodes.values())
        nodes[0].sessions = [broker.parse_session(session(), nodes[0].host)]
        def reply(node, command):
            data = status()
            if node is nodes[0]:
                data["sessions"] = ["broken"]
            return data
        with patch.object(self.farm, "_ssh", side_effect=reply):
            self.farm.poll_once()
        self.assertFalse(nodes[0].online)
        self.assertEqual(len(nodes[0].sessions), 1)  # retain last known sessions
        self.assertTrue(nodes[0].last_error)
        self.assertTrue(all(n.online and n.last_ok > 0 for n in nodes[1:]))

    def test_invalid_metrics_are_rejected(self):
        node = next(iter(self.farm.nodes.values()))
        for key, value in (("load1", float("nan")), ("mem_avail", 101),
                           ("cpus", 0), ("cpus", True), ("sessions", None)):
            data = status()
            data[key] = value
            with self.subTest(key=key, value=value), patch.object(self.farm, "_ssh", return_value=data):
                _, received, error = self.farm._poll_one(node)
                self.assertIsNone(received)
                self.assertTrue(error)

    def test_client_event_requires_owner_and_pool(self):
        node = next(iter(self.farm.nodes.values()))
        node.sessions = [broker.parse_session(session(), node.host)]
        params = {"sid": "sid1", "server": node.host, "client": "device"}
        self.assertFalse(self.farm.client_event("attacker", params, "192.0.2.2", {node.pool}))
        self.assertFalse(self.farm.client_event("ivanov", params, "192.0.2.2", set()))
        self.assertEqual(self.farm.client_events, {})
        self.assertTrue(self.farm.client_event("ivanov", params, "192.0.2.2", {node.pool}))
        self.assertEqual(self.farm.snapshot()["sessions"][0]["client_event"]["client"], "device")

    def test_same_sid_on_other_node_is_not_annotated(self):
        nodes = list(self.farm.nodes.values())[:2]
        for node in nodes:
            node.sessions = [broker.parse_session(session(), node.host)]
        self.farm.client_event("ivanov", {"sid": "sid1", "server": nodes[0].host},
                               "192.0.2.2", {nodes[0].pool})
        sessions = self.farm.snapshot()["sessions"]
        self.assertIn("client_event", sessions[0])
        self.assertNotIn("client_event", sessions[1])

    def test_simultaneous_assignments_do_not_overbook(self):
        for node in self.farm.pool_nodes("1c-buh"):
            node.max_sessions = 2
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(lambda i: self.farm.select(f"u{i}", "192.0.2.1", "1c-buh"), range(20)))
        self.assertEqual(sum(node is not None for node, _, _ in results), 4)
        self.assertTrue(all(len(n.reservations) == 2 for n in self.farm.pool_nodes("1c-buh")))

    def test_negative_body_length_is_rejected(self):
        handler = Mock(headers={"Content-Length": "-1"})
        with self.assertRaises(ValueError):
            broker.Handler.read_body(handler)
        handler.rfile.read.assert_not_called()


class AgentTests(unittest.TestCase):
    def test_list_command_error_is_not_empty_farm(self):
        result = subprocess.CompletedProcess([], 1, "", "database unavailable")
        with patch.object(agent, "which", return_value="/usr/bin/x2golistsessions_root"), \
                patch.object(agent.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            agent.list_sessions()

    def test_malformed_output_is_rejected(self):
        result = subprocess.CompletedProcess([], 0, "broken\n", "")
        with patch.object(agent, "which", return_value="/usr/bin/x2golistsessions_root"), \
                patch.object(agent.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            agent.list_sessions()

    def test_empty_successful_list_is_valid(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(agent, "which", return_value="/usr/bin/x2golistsessions_root"), \
                patch.object(agent.subprocess, "run", return_value=result):
            self.assertEqual(agent.list_sessions(), [])

    def test_failed_termination_never_kills_unverified_pid(self):
        for failure in (subprocess.CompletedProcess([], 1, "", "failed"),
                        subprocess.TimeoutExpired("terminate", 30)):
            with self.subTest(failure=failure):
                kwargs = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                output = io.StringIO()
                with patch.object(agent, "find_session", return_value=session().split("|")), \
                        patch.object(agent, "which", return_value="/usr/bin/x2goterminate-session"), \
                        patch.object(agent, "run_as", **kwargs), \
                        patch.object(agent.os, "kill") as kill, redirect_stdout(output):
                    with self.assertRaises(SystemExit) as exc:
                        agent.cmd_action("terminate", "sid1")
                    self.assertEqual(exc.exception.code, 1)
                    kill.assert_not_called()
                self.assertIn('"ok": false', output.getvalue())


if __name__ == "__main__":
    unittest.main()
