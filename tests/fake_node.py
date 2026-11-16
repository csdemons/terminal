#!/usr/bin/python3
"""Имитация x2go-node-agent для тестов: состояние узлов в JSON-файле.

fake_node.py <state.json> <host> "<command>"
Узел с "down": true ведёт себя как зависший (не отвечает).
"""
import json
import sys
import time

path, host, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as fh:
    farm = json.load(fh)
node = farm[host]
if node.get("down"):
    time.sleep(0.2)
    print("ssh: connect to host %s port 22: Connection timed out" % host, file=sys.stderr)
    sys.exit(255)

parts = cmd.split()
if parts == ["status"]:
    lines = []
    for s in node["sessions"]:
        # agent_pid|session_id|display|server|status|init_time|cookie|client|gr|snd|last|user|age|fs
        lines.append("|".join([str(s.get("pid", 1000)), s["sid"], "50", host.split(".")[0],
                               s["status"], "2026-11-16T09:00:00", "cookie", "10.1.1.5",
                               "30001", "30002", s.get("last", "2026-11-16T10:00:00"),
                               s["user"], "3600", "30003"]))
    print(json.dumps({"ok": True, "hostname": host, "cpus": node.get("cpus", 32),
                      "load1": node.get("load1", 1.0), "load5": 1.0,
                      "mem_total": 256 << 30, "mem_avail": node.get("mem_avail_gb", 200) << 30,
                      "uptime": 1000, "list_ms": 5, "sessions": lines}))
elif len(parts) == 2 and parts[0] in ("suspend", "terminate"):
    for s in node["sessions"]:
        if s["sid"] == parts[1]:
            if parts[0] == "terminate":
                node["sessions"].remove(s)
            else:
                s["status"] = "S"
            with open(path, "w") as fh:
                json.dump(farm, fh)
            print(json.dumps({"ok": True, "user": s["user"], "forced": False, "detail": ""}))
            break
    else:
        print(json.dumps({"ok": False, "error": "сессия не найдена"}))
else:
    print(json.dumps({"ok": False, "error": "неизвестная команда"}))
