#!/usr/bin/python3
"""Сквозной тест брокера на имитации фермы из трёх узлов.

Запуск: python3 tests/test_broker.py
Разбор ответов повторяет логику HttpBrokerClient из X2Go Client.
"""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="x2gobroker-test-"))
STATE = TMP / "farm.json"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


PORT = free_port()
URL = f"http://127.0.0.1:{PORT}/plain/"


def set_farm(farm):
    STATE.write_text(json.dumps(farm))


def post(params, path="/plain/"):
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode() + "|" + e.reason


def client_parse_session(answer):
    """Как HttpBrokerClient::checkAccess + parseSession."""
    assert "Access granted" in answer, answer
    lst = [p for p in answer.split("SERVER:") if p]
    host, port = lst[1].split("\n")[0].split(":")
    sessions = []
    if "SESSION_INFO" in answer:
        sessions = [l for l in answer.split("SESSION_INFO:")[1].strip().split("\n") if l]
    return host, port, sessions


def admin(path, payload=None, user="admin", pw="adminpw"):
    hdr = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        hdr.update({"Content-Type": "application/json", "X-Broker-Admin": "1"})
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read().decode()
            return r.status, json.loads(body) if "json" in r.headers["Content-Type"] else body
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except json.JSONDecodeError:
            return e.code, None


def wait_poll():
    time.sleep(1.6)


def login(user="ivanov", pw="secret"):
    st, ans = post({"task": "selectsession", "sid": "rrcki-desktop",
                    "user": user, "password": pw, "authid": ""})
    return st, ans


checks = 0


def check(cond, msg):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        raise SystemExit(1)


def main():
    set_farm({
        "term-01.rrcki.ru": {"sessions": [{"sid": "a1", "user": "petrov", "status": "R"}] * 1 +
                             [{"sid": f"x{i}", "user": f"u{i}", "status": "R"} for i in range(5)]},
        "term-02.rrcki.ru": {"sessions": [{"sid": "b1", "user": "sidorov", "status": "R"}]},
        "term-03.rrcki.ru": {"sessions": [{"sid": f"y{i}", "user": f"w{i}", "status": "R"} for i in range(3)]},
    })
    cfg = TMP / "broker.toml"
    cfg.write_text(f"""
[broker]
listen = "127.0.0.1:{PORT}"
state_file = "{TMP}/state.json"
audit_file = "{TMP}/audit.jsonl"
poll_interval = 1
offline_after = 2
node_command = ["{sys.executable}", "{ROOT}/tests/fake_node.py", "{STATE}", "{{host}}", "{{cmd}}"]

[auth]
backend = "static"
max_failures = 3
max_failures_per_ip = 12
[auth.static_users.ivanov]
password = "secret"
[auth.static_users.smirnov]
password = "secret"
[auth.static_users.kuznetsov]
password = "secret"
[auth.static_users.outsider]
password = "secret"
roles = []
[auth.static_users.admin]
password = "adminpw"
roles = ["admin", "user"]
[auth.static_users.viewer]
password = "v"
roles = ["viewer"]
[auth.static_users.officer]
password = "o"
roles = ["officer"]
[auth.static_users.sec]
password = "s"
roles = ["security"]

[balancing]
max_sessions_per_node = 10
reserve_seconds = 60

[[nodes]]
host = "term-01.rrcki.ru"
[[nodes]]
host = "term-02.rrcki.ru"
[[nodes]]
host = "term-03.rrcki.ru"

[[profiles]]
id = "rrcki-desktop"
name = "Рабочий стол РРЦКИ"
command = "MATE"
fullscreen = true
""")
    proc = subprocess.Popen([sys.executable, str(ROOT / "broker/rrcki_x2gobroker.py"), "-c", str(cfg)],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        for _ in range(50):
            try:
                if post({"task": "testcon"})[0] == 200:
                    break
            except OSError:
                time.sleep(0.1)
        wait_poll()

        print("Протокол и аутентификация")
        st, ans = post({"task": "testcon"})
        check(st == 200 and "Access granted" in ans, "testcon")
        st, ans = post({"task": "listsessions", "user": "RRCKI\\Ivanov", "password": "secret", "authid": ""})
        body = ans.split("START_USER_SESSIONS\n")[1].split("END_USER_SESSIONS\n")[0]
        check("[rrcki-desktop]" in body and "user=ivanov" in body and "usebrokerpass=true" in body
              and "fullscreen=true" in body and "name=Рабочий стол РРЦКИ" in body,
              "listsessions: профиль, нормализация RRCKI\\Ivanov → ivanov, usebrokerpass")
        st, ans = login(pw="wrong")
        check("Access granted" not in ans, "неверный пароль → отказ")
        st, ans = login(user="outsider")
        check("Access granted" not in ans, "пользователь не из группы доступа → отказ")
        st, ans = post({"task": "listsessions", "user": "ivanov", "password": "", "authid": ""})
        check("Access granted" not in ans, "пустой пароль → отказ")

        print("Выбор узла")
        host, port, sess = client_parse_session(login()[1])
        check(host == "term-02.rrcki.ru" and port == "22" and not sess,
              f"новая сессия на самом свободном узле (term-02), получено {host}")
        client_parse_session(login()[1])
        st, snap = admin("/admin/api/state")
        n2 = next(n for n in snap["nodes"] if n["host"] == "term-02.rrcki.ru")
        check(n2["reserved"] == 1, "повторный вход того же пользователя не удваивает резерв")
        for u in ("smirnov", "admin"):
            client_parse_session(login(user=u, pw="secret" if u != "admin" else "adminpw")[1])
        # term-02: 1 сессия + 3 резерва (ivanov, smirnov, admin) = 0.4 > term-03: 3 сессии = 0.3
        host2, _, _ = client_parse_session(login(user="kuznetsov")[1])
        snap = admin("/admin/api/state")[1]
        res = {n["host"]: n["reserved"] for n in snap["nodes"]}
        check(host2 == "term-03.rrcki.ru" and res["term-02.rrcki.ru"] == 3 and res["term-03.rrcki.ru"] == 1,
              f"резервы учитываются: при заполнении term-02 вход уходит на term-03 ({host2}, {res})")

        print("Возврат в существующую сессию")
        farm = json.loads(STATE.read_text())
        farm["term-03.rrcki.ru"]["sessions"].append({"sid": "iv-1", "user": "ivanov", "status": "S"})
        set_farm(farm)
        wait_poll()
        host, _, sess = client_parse_session(login()[1])
        check(host == "term-03.rrcki.ru" and len(sess) == 1 and "|iv-1|" in sess[0] and "|S|" in sess[0],
              "приостановленная сессия → тот же узел и SESSION_INFO")

        print("Отказ узла")
        farm = json.loads(STATE.read_text())
        farm["term-03.rrcki.ru"]["down"] = True
        set_farm(farm)
        time.sleep(3.5)
        st, snap = admin("/admin/api/state")
        n3 = next(n for n in snap["nodes"] if n["host"] == "term-03.rrcki.ru")
        check(not n3["online"], "зависший узел помечен недоступным")
        host, _, sess = client_parse_session(login()[1])
        check(host != "term-03.rrcki.ru" and not sess,
              f"сессия на упавшем узле → новый вход на исправный узел ({host})")
        lost = [s for s in snap["sessions"] if not s["node_online"] and s["user"] == "ivanov"]
        check(len(lost) == 1, "панель показывает сессию на недоступном узле")
        st, res = admin("/admin/api/action", {"action": "forget", "host": "term-03.rrcki.ru", "sid": "iv-1"})
        check(res["ok"], "сброс сессии упавшего узла из учёта")

        print("Обслуживание узла")
        st, res = admin("/admin/api/action", {"action": "drain", "host": "term-02.rrcki.ru"})
        check(res["ok"], "узел term-02 выведен")
        host, _, _ = client_parse_session(login(user="smirnov")[1])
        check(host == "term-01.rrcki.ru", f"на выведенный узел новые сессии не идут ({host})")
        farm = json.loads(STATE.read_text())
        farm["term-02.rrcki.ru"]["sessions"].append({"sid": "sm-1", "user": "smirnov", "status": "S"})
        set_farm(farm)
        wait_poll()
        host, _, sess = client_parse_session(login(user="smirnov")[1])
        check(host == "term-02.rrcki.ru" and sess,
              "но в свою сессию на выведенном узле пользователь возвращается")
        state = json.loads((TMP / "state.json").read_text())
        check(state["drained"] == ["term-02.rrcki.ru"], "флаг обслуживания сохранён на диск")

        print("Действия администратора")
        st, res = admin("/admin/api/action", {"action": "terminate", "host": "term-02.rrcki.ru", "sid": "sm-1"})
        check(res["ok"], "завершение сессии на узле")
        time.sleep(0.8)
        host, _, sess = client_parse_session(login(user="smirnov")[1])
        check(host != "term-02.rrcki.ru" and not sess,
              f"после завершения пользователь попадает на свободный узел ({host})")
        st, _ = admin("/admin/api/state", user="ivanov", pw="secret")
        check(st == 403, "обычный пользователь (без роли панели) получает 403")
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/admin/api/action",
                                     data=b'{"action":"drain","host":"term-01.rrcki.ru"}',
                                     headers={"Authorization": "Basic " + base64.b64encode(b"admin:adminpw").decode()})
        try:
            urllib.request.urlopen(req)
            check(False, "действие без X-Broker-Admin отклонено")
        except urllib.error.HTTPError as e:
            check(e.code == 403, "действие без X-Broker-Admin отклонено (защита от CSRF)")
        st, page = admin("/admin")
        check(st == 200 and "Ферма X2Go" in page, "страница панели отдаётся")

        print("Роли панели")
        st, snap = admin("/admin/api/state", user="viewer", pw="v")
        check(st == 200 and snap["perms"] == ["view"], "viewer видит ферму, права только view")
        st, res = admin("/admin/api/action", {"action": "drain", "host": "term-01.rrcki.ru"}, "viewer", "v")
        check(st == 403 and not res["ok"], "viewer не может вывести узел")
        sid = next(x["sid"] for x in snap["sessions"] if x["node"] == "term-01.rrcki.ru")
        st, res = admin("/admin/api/action", {"action": "terminate", "host": "term-01.rrcki.ru", "sid": sid},
                        "viewer", "v")
        check(st == 403, "viewer не может завершать сессии")
        st, res = admin("/admin/api/action", {"action": "suspend", "host": "term-01.rrcki.ru", "sid": sid},
                        "officer", "o")
        check(st == 200 and res["ok"], "officer приостанавливает сессию пользователя")
        st, res = admin("/admin/api/action", {"action": "drain", "host": "term-03.rrcki.ru"}, "officer", "o")
        check(st == 403, "officer не может выводить узлы")
        st, _ = admin("/admin/api/audit", user="admin", pw="adminpw")
        check(st == 403, "admin не читает журнал аудита (разделение обязанностей)")
        st, _ = admin("/admin/api/audit.csv", user="admin", pw="adminpw")
        check(st == 403, "admin не выгружает журнал аудита")
        st, res = admin("/admin/api/action", {"action": "terminate", "host": "term-01.rrcki.ru", "sid": sid},
                        "sec", "s")
        check(st == 403, "security не управляет сессиями")
        st, a = admin("/admin/api/audit", user="sec", pw="s")
        ev = [r["event"] for r in a["records"]]
        check(st == 200 and a["integrity"]["ok"], "security читает журнал, цепочка цела")
        check({"auth.fail", "broker.route", "node.drain", "session.terminate", "session.suspend",
               "session.forget", "access.denied", "service.start"} <= set(ev),
              "в аудите есть входы, отказы, маршрутизация и действия всех ролей")
        denied = [r for r in a["records"] if r["event"] == "access.denied" and r["actor"] == "admin"]
        check(denied and "audit" in denied[0]["details"]["reason"],
              "попытка admin открыть аудит сама записана в аудит")
        term = next(r for r in a["records"] if r["event"] == "session.suspend")
        check(term["actor"] == "officer" and term["details"]["owner"],
              "запись о действии содержит исполнителя и владельца сессии")
        st, page = admin("/admin", user="outsider", pw="secret")
        check(st == 403, "пользователь без роли панели не входит в панель")

        print("Нет свободных узлов")
        admin("/admin/api/action", {"action": "drain", "host": "term-01.rrcki.ru"})
        st, ans = login(user="ivanov")
        check(st == 503 and "No free terminal servers" in ans, "503 с понятной причиной вместо краха клиента")

        print("Блокировка перебора")
        for _ in range(4):
            login(user="smirnov", pw="bad")
        st, ans = login(user="smirnov")
        check("Access granted" not in ans, "после серии неверных паролей вход временно заблокирован")
        st, a = admin("/admin/api/audit?event=auth.", user="sec", pw="s")
        keys = [l["key"] for l in a["lockouts"]]
        check("u:smirnov" in keys and any(r["event"] == "auth.lockout" for r in a["records"]),
              "блокировка видна безопасности и записана в аудит")
        st, res = admin("/admin/api/action", {"action": "unlock", "key": "u:smirnov"}, "admin", "adminpw")
        check(st == 403, "admin не снимает блокировки")
        st, res = admin("/admin/api/action", {"action": "unlock", "key": "u:smirnov"}, "sec", "s")
        check(res["ok"], "security снимает блокировку")
        st, ans = post({"task": "listsessions", "user": "smirnov", "password": "secret", "authid": ""})
        check(st == 200 and "Access granted" in ans, "после снятия блокировки пользователь входит")
        st, csv_body = admin("/admin/api/audit.csv", user="sec", pw="s")
        check(st == 200 and csv_body.startswith("\ufeffвремя;событие"), "выгрузка CSV для безопасности")

        print("Целостность журнала аудита")
        audit = TMP / "audit.jsonl"
        r = subprocess.run([sys.executable, str(ROOT / "broker/rrcki_x2gobroker.py"),
                            "--verify-audit", str(audit)], capture_output=True, text=True)
        check(r.returncode == 0, "проверка цепочки: " + r.stdout.strip())
        lines = audit.read_text().splitlines()
        tampered = TMP / "tampered.jsonl"
        tampered.write_text("\n".join(lines[:3] + [lines[3].replace('"result":"denied"', '"result":"ok"')
                                                    .replace('"result":"ok"', '"result":"denied"')] + lines[4:]) + "\n")
        r = subprocess.run([sys.executable, str(ROOT / "broker/rrcki_x2gobroker.py"),
                            "--verify-audit", str(tampered)], capture_output=True, text=True)
        check(r.returncode == 2 and "строке 4" in r.stdout, "правка записи обнаружена")
        tampered.write_text("\n".join(lines[:5] + lines[6:]) + "\n")
        r = subprocess.run([sys.executable, str(ROOT / "broker/rrcki_x2gobroker.py"),
                            "--verify-audit", str(tampered)], capture_output=True, text=True)
        check(r.returncode == 2 and "разрыв цепочки" in r.stdout, "удаление записи обнаружено")

        print(f"\nВсе проверки пройдены: {checks}")
    finally:
        proc.terminate()
        out, _ = proc.communicate(timeout=5)
        if os.environ.get("SHOW_LOG"):
            print(out)


if __name__ == "__main__":
    main()
