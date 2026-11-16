#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
rrcki-x2gobroker — лёгкий брокер сессий X2Go.

* Говорит на HTTP-протоколе штатного X2Go Client (--broker-url):
  testcon, listsessions, selectsession, clientevent.
* Проверяет логин и пароль в AD (LDAP bind) и членство в группе доступа.
* Раз в несколько секунд опрашивает узлы фермы через x2go-node-agent по SSH.
* Возвращает пользователя в его сессию, если она жива; иначе выбирает
  самый свободный узел. Упавшие и выведенные на обслуживание узлы обходит.
* Панель /admin с ролями viewer, officer, admin, security и журнал аудита
  с цепочкой хешей (защита от незаметной правки записей).

Зависимости: Python 3.11+ (tomllib), python3-ldap3 (для backend = "ldap").
"""
import argparse
import datetime
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import tomllib
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

log = logging.getLogger("x2gobroker")
HERE = Path(__file__).resolve().parent
USER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SID_RE = re.compile(r"^[A-Za-z0-9._+@-]{1,200}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


# --------------------------------------------------------------------------- #
# Конфигурация
# --------------------------------------------------------------------------- #

DEFAULTS = {
    "broker": {
        "listen": "127.0.0.1:8080",
        "state_file": "/var/lib/rrcki-x2gobroker/state.json",
        "poll_interval": 10,
        "offline_after": 3,
        "ssh_user": "x2gobroker",
        "ssh_key": "/etc/rrcki-x2gobroker/node_key",
        "known_hosts": "/etc/rrcki-x2gobroker/known_hosts",
        "ssh_timeout": 8,
        "trusted_proxies": ["127.0.0.1", "::1"],
        "audit_file": "/var/log/rrcki-x2gobroker/audit.jsonl",
        "node_command": [],          # переопределение для тестов
    },
    "auth": {
        "backend": "ldap",
        "ldap_uri": [],
        "domain": "",
        "base_dn": "",
        "users_group": "",           # кому разрешён вход на терминальную ферму
        "roles": {},                 # роль панели -> DN группы AD
        "admins_group": "",          # устаревшее имя для roles.admin
        "ca_file": "",
        "cache_seconds": 120,
        "max_failures": 8,           # неудачных попыток на одну учётную запись
        "max_failures_per_ip": 40,   # на один адрес (через NAT/VPN ходят многие)
        "lockout_seconds": 300,
        "static_users": {},
    },
    "balancing": {
        "max_sessions_per_node": 40,
        "min_free_mem_percent": 10,
        "reserve_seconds": 60,
        "load_weight": 0.3,
        "ssh_port": 22,
    },
}


def load_config(path):
    with open(path, "rb") as fh:
        raw = tomllib.load(fh)
    cfg = {}
    for section, defaults in DEFAULTS.items():
        merged = dict(defaults)
        merged.update(raw.get(section, {}))
        cfg[section] = merged
    cfg["nodes"] = raw.get("nodes", [])
    cfg["profiles"] = raw.get("profiles", [])
    if not cfg["nodes"]:
        raise SystemExit("В конфигурации нет ни одного [[nodes]]")
    if not cfg["profiles"]:
        raise SystemExit("В конфигурации нет ни одного [[profiles]]")
    for n in cfg["nodes"]:
        if not HOST_RE.match(n.get("host", "")):
            raise SystemExit(f"Некорректное имя узла: {n.get('host')!r}")
    for p in cfg["profiles"]:
        if not re.match(r"^[A-Za-z0-9_-]{1,64}$", p.get("id", "")):
            raise SystemExit(f"Некорректный id профиля: {p.get('id')!r}")
    return cfg


# --------------------------------------------------------------------------- #
# Роли
# --------------------------------------------------------------------------- #

# Права панели. Роли суммируются, если пользователь состоит в нескольких группах.
#   view      — видеть узлы, сессии, оперативный журнал
#   sessions  — приостанавливать, завершать, сбрасывать сессии пользователей
#   nodes     — выводить узлы на обслуживание и возвращать
#   audit     — читать и выгружать журнал аудита, проверять его целостность
#   unlock    — снимать блокировку входа после перебора паролей
ROLE_PERMS = {
    "viewer":   {"view"},
    "officer":  {"view", "sessions"},
    "admin":    {"view", "sessions", "nodes"},
    "security": {"view", "audit", "unlock"},
}
ROLE_TITLES = {"viewer": "наблюдатель", "officer": "дежурный",
               "admin": "администратор", "security": "безопасность"}
PANEL_ROLES = tuple(ROLE_PERMS)


def perms_of(roles):
    out = set()
    for r in roles or ():
        out |= ROLE_PERMS.get(r, set())
    return out


# --------------------------------------------------------------------------- #
# Журнал аудита
# --------------------------------------------------------------------------- #

def _canon(rec):
    return json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Audit:
    """Журнал аудита: JSON Lines, каждая запись содержит хеш предыдущей.

    Удаление, вставка или правка записи в середине файла обнаруживается
    проверкой цепочки (--verify-audit, панель безопасности). Копия каждой
    записи уходит в syslog (logger x2gobroker.audit) для отправки в SIEM:
    от того, у кого есть root на ВМ брокера, защищает только внешняя копия.
    """

    GENESIS = "0" * 64

    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        self.sys = logging.getLogger("x2gobroker.audit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.prev = self._last_hash()
        self._verify_cache = None

    def _last_hash(self):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, 2)
                fh.seek(max(0, fh.tell() - 65536))
                lines = fh.read().splitlines()
        except FileNotFoundError:
            return self.GENESIS
        for line in reversed(lines):
            try:
                return json.loads(line)["hash"]
            except Exception:  # noqa: BLE001
                continue
        return self.GENESIS

    def write(self, event, actor="", ip="", result="ok", /, **details):
        with self.lock:
            rec = {"ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                   "event": event, "actor": actor or "", "ip": ip or "",
                   "result": result, "details": details, "prev": self.prev}
            rec["hash"] = hashlib.sha256(_canon(rec).encode()).hexdigest()
            line = _canon(rec) + "\n"
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    os.fsync(fh.fileno())
                self.prev = rec["hash"]
            except OSError as exc:
                log.error("АУДИТ НЕ ЗАПИСАН (%s): %s", exc, line.strip())
        self.sys.info("%s actor=%s ip=%s result=%s %s", event, actor, ip, result,
                      _canon(details))

    @classmethod
    def verify_file(cls, path):
        """-> {'ok', 'records', 'error', 'line'}; первая запись может продолжать
        цепочку предыдущего (архивного) файла."""
        prev, n = None, 0
        try:
            fh = open(path, encoding="utf-8")
        except FileNotFoundError:
            return {"ok": True, "records": 0, "error": "", "line": 0}
        with fh:
            for n, line in enumerate(fh, 1):
                try:
                    rec = json.loads(line)
                    h = rec.pop("hash")
                except Exception:  # noqa: BLE001
                    return {"ok": False, "records": n - 1, "line": n,
                            "error": "строка повреждена"}
                if hashlib.sha256(_canon(rec).encode()).hexdigest() != h:
                    return {"ok": False, "records": n - 1, "line": n,
                            "error": "запись изменена (хеш не совпадает)"}
                if prev is not None and rec.get("prev") != prev:
                    return {"ok": False, "records": n - 1, "line": n,
                            "error": "разрыв цепочки (запись удалена или вставлена)"}
                prev = h
        return {"ok": True, "records": n, "error": "", "line": 0}

    def verify(self):
        try:
            st = self.path.stat()
            key = (st.st_size, st.st_mtime_ns)
        except FileNotFoundError:
            key = None
        if self._verify_cache and self._verify_cache[0] == key:
            return self._verify_cache[1]
        res = self.verify_file(self.path)
        self._verify_cache = (key, res)
        return res

    def tail(self, limit=500, query="", event_prefix="", max_bytes=8 << 20):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - max_bytes))
                lines = fh.read().decode("utf-8", "replace").splitlines()
            if size > max_bytes:
                lines = lines[1:]
        except FileNotFoundError:
            return []
        q = query.lower()
        out = []
        for line in reversed(lines):
            if q and q not in line.lower():
                continue
            try:
                rec = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if event_prefix and not rec.get("event", "").startswith(event_prefix):
                continue
            rec.pop("prev", None)
            out.append(rec)
            if len(out) >= limit:
                break
        return out


# --------------------------------------------------------------------------- #
# Аутентификация
# --------------------------------------------------------------------------- #

def normalize_user(raw):
    """RRCKI\\Ivanov, ivanov@rrcki.ru, Ivanov -> ivanov."""
    u = (raw or "").strip()
    if "\\" in u:
        u = u.split("\\", 1)[1]
    if "@" in u:
        u = u.split("@", 1)[0]
    u = u.lower()
    return u if USER_RE.match(u) else None


class Authenticator:
    """Проверка пароля в AD с кэшем успешных входов и блокировкой перебора."""

    def __init__(self, cfg, audit):
        self.cfg = cfg
        self.audit = audit
        self.backend = cfg["backend"]
        # Роли панели из [auth.roles]; admins_group — для старых конфигураций.
        self.role_groups = {r: g for r, g in cfg["roles"].items() if g}
        if cfg["admins_group"] and "admin" not in self.role_groups:
            self.role_groups["admin"] = cfg["admins_group"]
        unknown = set(self.role_groups) - set(PANEL_ROLES)
        if unknown:
            raise SystemExit(f"[auth.roles] неизвестные роли: {', '.join(sorted(unknown))}; "
                             f"допустимы: {', '.join(PANEL_ROLES)}")
        self._secret = secrets.token_bytes(32)
        self._cache = {}         # user -> (digest, roles, expires)
        self._fails = {}         # key -> deque[timestamps]
        self._panel_seen = {}    # user -> время последней записи входа в панель в аудит
        self._lock = threading.Lock()
        if self.backend == "static":
            log.warning("Аутентификация backend=static: ТОЛЬКО ДЛЯ ТЕСТОВ")
        elif self.backend == "ldap":
            import ldap3  # noqa: F401 — проверить наличие пакета при старте
            for key in ("ldap_uri", "domain", "base_dn", "users_group"):
                if not cfg[key]:
                    raise SystemExit(f"[auth] не задан {key}")
        else:
            raise SystemExit(f"Неизвестный backend аутентификации: {self.backend}")

    def _limit(self, key):
        return self.cfg["max_failures_per_ip"] if key.startswith("ip:") else self.cfg["max_failures"]

    def _digest(self, user, password):
        return hmac.new(self._secret, f"{user}\0{password}".encode(), hashlib.sha256).digest()

    def locked(self, *keys):
        now = time.time()
        window = self.cfg["lockout_seconds"]
        with self._lock:
            for k in keys:
                q = self._fails.get(k)
                if not q:
                    continue
                while q and q[0] < now - window:
                    q.popleft()
                if len(q) >= self._limit(k):
                    return True
        return False

    def _fail(self, *keys):
        newly_locked = []
        with self._lock:
            for k in keys:
                q = self._fails.setdefault(k, deque(maxlen=200))
                q.append(time.time())
                if len(q) == self._limit(k):
                    newly_locked.append(k)
        return newly_locked

    def lockouts(self):
        """Текущие блокировки: [{'key', 'kind', 'value', 'failures', 'until'}]."""
        now = time.time()
        window = self.cfg["lockout_seconds"]
        out = []
        with self._lock:
            for k, q in self._fails.items():
                recent = [t for t in q if t >= now - window]
                limit = self._limit(k)
                if len(recent) >= limit:
                    kind, _, value = k.partition(":")
                    out.append({"key": k, "kind": "user" if kind == "u" else "ip",
                                "value": value, "failures": len(recent),
                                "until": recent[-limit] + window})
        return sorted(out, key=lambda x: -x["until"])

    def unlock(self, key):
        with self._lock:
            if key not in self._fails:
                raise KeyError("такой блокировки нет")
            del self._fails[key]

    def invalidate(self, user):
        with self._lock:
            self._cache.pop(user, None)

    def authenticate(self, user, password, ip, channel="terminal"):
        """Возвращает множество ролей ('user' и роли панели) или None."""
        if not user or not password:
            return None   # пустой пароль в AD = анонимный bind, его надо отсечь
        if self.locked(f"u:{user}", f"ip:{ip}"):
            log.warning("Вход заблокирован после неудачных попыток: user=%s ip=%s", user, ip)
            self.audit.write("auth.blocked", user, ip, "denied", channel=channel)
            return None
        dig = self._digest(user, password)
        now = time.time()
        with self._lock:
            hit = self._cache.get(user)
            if hit and hit[2] > now and hmac.compare_digest(hit[0], dig):
                return hit[1]
        try:
            roles = self._check_static(user, password) if self.backend == "static" \
                else self._check_ldap(user, password)
        except Exception as exc:  # noqa: BLE001
            log.error("Ошибка обращения к каталогу для %s: %s", user, exc)
            self.audit.write("auth.error", user, ip, "error", channel=channel, error=str(exc)[:300])
            return None
        if roles is None:
            locked = self._fail(f"u:{user}", f"ip:{ip}")
            log.info("Неверный логин или пароль: user=%s ip=%s", user, ip)
            self.audit.write("auth.fail", user, ip, "denied", channel=channel)
            for k in locked:
                self.audit.write("auth.lockout", user, ip, "denied", channel=channel, key=k,
                                 minutes=round(self.cfg["lockout_seconds"] / 60))
            return None
        with self._lock:
            self._cache[user] = (dig, roles, now + self.cfg["cache_seconds"])
            # Панель переспрашивает каталог каждые cache_seconds; в аудит — раз в 30 минут.
            quiet = channel == "panel" and now - self._panel_seen.get(user, 0) < 1800
            if channel == "panel":
                self._panel_seen.setdefault(user, now)
                if not quiet:
                    self._panel_seen[user] = now
        if not quiet:
            self.audit.write("auth.ok", user, ip, "ok", channel=channel, roles=sorted(roles))
        return roles

    def _check_static(self, user, password):
        rec = self.cfg["static_users"].get(user)
        if not rec or not hmac.compare_digest(rec.get("password", ""), password):
            return None
        return set(rec.get("roles", ["user"]))

    def _check_ldap(self, user, password):
        import ldap3
        from ldap3.utils.conv import escape_filter_chars

        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED,
                        ca_certs_file=self.cfg["ca_file"] or None)
        servers = []
        for uri in self.cfg["ldap_uri"]:
            servers.append(ldap3.Server(uri, use_ssl=uri.startswith("ldaps://"),
                                        tls=tls, connect_timeout=5, get_info=ldap3.NONE))
        pool = ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=60)
        conn = ldap3.Connection(pool, user=f"{user}@{self.cfg['domain']}",
                                password=password, authentication=ldap3.SIMPLE,
                                receive_timeout=10, raise_exceptions=False,
                                read_only=True)
        try:
            if not conn.open():
                raise RuntimeError(f"нет связи с контроллером домена: {conn.result}")
            if not conn.server.ssl:   # ldap:// — пароль только поверх StartTLS
                if not conn.start_tls():
                    raise RuntimeError("не удалось включить StartTLS")
            if not conn.bind():
                return None
            u = escape_filter_chars(user)
            roles = set()
            # 1.2.840.113556.1.4.1941 — проверка членства с учётом вложенных групп
            for role, group in [("user", self.cfg["users_group"])] + list(self.role_groups.items()):
                g = escape_filter_chars(group)
                conn.search(self.cfg["base_dn"],
                            f"(&(objectCategory=person)(sAMAccountName={u})"
                            f"(memberOf:1.2.840.113556.1.4.1941:={g})"
                            f"(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                            attributes=["sAMAccountName"], size_limit=1)
                if conn.entries:
                    roles.add(role)
            return roles
        finally:
            try:
                conn.unbind()
            except Exception:  # noqa: BLE001
                pass


# --------------------------------------------------------------------------- #
# Узлы и сессии
# --------------------------------------------------------------------------- #

def parse_session(line, host):
    f = line.split("|")
    return {
        "raw": line,
        "pid": f[0], "sid": f[1], "display": f[2], "server": f[3],
        "status": f[4], "started": f[5], "client_ip": f[7],
        "last": f[10], "user": f[11].lower(), "node": host,
    }


class Node:
    def __init__(self, spec, bal):
        self.host = spec["host"]
        self.label = spec.get("label", self.host)
        self.weight = float(spec.get("weight", 1.0))
        self.max_sessions = int(spec.get("max_sessions", bal["max_sessions_per_node"]))
        self.ssh_port = int(spec.get("ssh_port", bal["ssh_port"]))
        self.online = False
        self.ever_seen = False
        self.fails = 0
        self.last_ok = 0.0
        self.last_error = "ещё не опрашивался"
        self.status = {}
        self.sessions = []
        self.drained = False
        self.reservations = {}   # user -> время, когда брокер отправил его сюда

    def reserved(self, now, ttl):
        """Места, отданные пользователям, чьи сессии ещё не появились в опросе."""
        for user, ts in list(self.reservations.items()):
            if ts < now - ttl:
                del self.reservations[user]
        return len(self.reservations)

    def set_sessions(self, sessions):
        self.sessions = sessions
        for s in sessions:
            self.reservations.pop(s["user"], None)

    def mem_free_pct(self):
        tot = self.status.get("mem_total") or 0
        return 100.0 * self.status.get("mem_avail", 0) / tot if tot else 0.0

    def to_dict(self, now, ttl):
        st = self.status
        return {
            "host": self.host, "label": self.label, "online": self.online,
            "ever_seen": self.ever_seen, "drained": self.drained, "fails": self.fails,
            "last_ok": self.last_ok, "last_error": self.last_error,
            "weight": self.weight, "max_sessions": self.max_sessions,
            "sessions_total": len(self.sessions),
            "sessions_running": sum(1 for s in self.sessions if s["status"] == "R"),
            "sessions_suspended": sum(1 for s in self.sessions if s["status"] == "S"),
            "reserved": self.reserved(now, ttl),
            "cpus": st.get("cpus"), "load1": st.get("load1"), "load5": st.get("load5"),
            "mem_total": st.get("mem_total"), "mem_avail": st.get("mem_avail"),
            "mem_free_pct": round(self.mem_free_pct(), 1) if st else None,
            "uptime": st.get("uptime"), "list_ms": st.get("list_ms"),
        }


class Farm:
    def __init__(self, cfg, audit):
        self.cfg = cfg
        self.audit = audit
        self.b = cfg["broker"]
        self.bal = cfg["balancing"]
        self.nodes = {n["host"]: Node(n, self.bal) for n in cfg["nodes"]}
        self.lock = threading.RLock()
        self.events = deque(maxlen=1000)
        self.client_events = {}     # sid -> последнее событие от клиента
        self.last_login = {}        # user -> {node, ip, time}
        self.pool = ThreadPoolExecutor(max_workers=min(32, len(self.nodes) + 4))
        self._stop = threading.Event()
        self.state_path = Path(self.b["state_file"])
        self._load_state()

    # ---- состояние на диске (только то, что задаёт администратор) ----
    def _load_state(self):
        try:
            data = json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return
        except Exception as exc:  # noqa: BLE001
            log.error("Не удалось прочитать %s: %s", self.state_path, exc)
            return
        for host in data.get("drained", []):
            if host in self.nodes:
                self.nodes[host].drained = True

    def _save_state(self):
        data = {"drained": sorted(h for h, n in self.nodes.items() if n.drained)}
        tmp = self.state_path.with_suffix(".tmp")
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1))
            os.replace(tmp, self.state_path)
        except OSError as exc:
            log.error("Не удалось сохранить %s: %s", self.state_path, exc)

    def event(self, kind, text, **extra):
        rec = {"time": time.time(), "kind": kind, "text": text, **extra}
        with self.lock:
            self.events.append(rec)
        log.info("[%s] %s", kind, text)

    # ---- связь с агентами ----
    def _ssh(self, node, command):
        b = self.b
        if b["node_command"]:
            argv = [a.replace("{host}", node.host).replace("{cmd}", command)
                    for a in b["node_command"]]
        else:
            argv = ["ssh", "-T", "-i", b["ssh_key"], "-p", str(node.ssh_port),
                    "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={b['ssh_timeout']}",
                    "-o", "StrictHostKeyChecking=yes",
                    "-o", f"UserKnownHostsFile={b['known_hosts']}",
                    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
                    "-o", "LogLevel=ERROR",
                    "-l", b["ssh_user"], node.host, command]
        res = subprocess.run(argv, capture_output=True, text=True,
                             timeout=b["ssh_timeout"] + 20, stdin=subprocess.DEVNULL)
        text = res.stdout.strip().splitlines()
        if not text:
            raise RuntimeError((res.stderr.strip() or f"код {res.returncode}, пустой ответ")[-300:])
        try:
            return json.loads(text[-1])
        except json.JSONDecodeError:
            raise RuntimeError(f"агент вернул не JSON: {text[-1][:200]}") from None

    def _poll_one(self, node):
        try:
            data = self._ssh(node, "status")
            if not data.get("ok"):
                raise RuntimeError(data.get("error", "ошибка агента"))
        except Exception as exc:  # noqa: BLE001
            return node, None, str(exc)
        return node, data, None

    def poll_once(self):
        futures = [self.pool.submit(self._poll_one, n) for n in self.nodes.values()]
        for fut in futures:
            node, data, err = fut.result()
            with self.lock:
                if data is not None:
                    was = node.online
                    node.status = {k: v for k, v in data.items() if k != "sessions"}
                    node.set_sessions([parse_session(l, node.host) for l in data["sessions"]])
                    node.fails = 0
                    node.online = True
                    node.ever_seen = True
                    node.last_ok = time.time()
                    node.last_error = ""
                    if not was:
                        self.event("node", f"Узел {node.host} в строю", host=node.host)
                else:
                    node.fails += 1
                    node.last_error = err
                    if node.online and node.fails >= self.b["offline_after"]:
                        node.online = False
                        self.event("node", f"Узел {node.host} недоступен: {err}",
                                   host=node.host, level="error")
                    elif not node.ever_seen and node.fails == 1:
                        log.warning("Узел %s не отвечает: %s", node.host, err)

    def run_poller(self):
        while not self._stop.is_set():
            t0 = time.monotonic()
            try:
                self.poll_once()
            except Exception:  # noqa: BLE001
                log.exception("Сбой цикла опроса")
            self._stop.wait(max(1.0, self.b["poll_interval"] - (time.monotonic() - t0)))

    def stop(self):
        self._stop.set()

    # ---- выбор узла ----
    def score(self, node, now):
        st = node.status
        busy = (len(node.sessions) + node.reserved(now, self.bal["reserve_seconds"])) / \
            max(1.0, node.max_sessions * node.weight)
        load = min(2.0, (st.get("load1") or 0) / max(1, st.get("cpus") or 1))
        return busy + self.bal["load_weight"] * load

    def eligible(self, node, now):
        if not node.online or node.drained:
            return False
        if node.mem_free_pct() < self.bal["min_free_mem_percent"]:
            return False
        used = len(node.sessions) + node.reserved(now, self.bal["reserve_seconds"])
        return used < node.max_sessions

    def select(self, user, ip):
        """-> (node, [строки сессий для возобновления], пояснение) или (None, [], причина)."""
        now = time.time()
        with self.lock:
            own = [s for n in self.nodes.values() for s in n.sessions if s["user"] == user]
            alive = [s for s in own if self.nodes[s["node"]].online]
            lost = [s for s in own if not self.nodes[s["node"]].online]
            if alive:
                # Приоритет: приостановленная, затем запущенная; среди них — самая свежая.
                alive.sort(key=lambda s: (s["status"] == "S", s["last"]), reverse=True)
                node = self.nodes[alive[0]["node"]]
                lines = [s["raw"] for s in alive if s["node"] == node.host]
                why = f"возврат в сессию {alive[0]['sid']} ({alive[0]['status']})"
            else:
                cands = [n for n in self.nodes.values() if self.eligible(n, now)]
                if not cands:
                    self.audit.write("broker.no_capacity", user, ip, "error")
                    return None, [], "нет свободных узлов"
                for n in self.nodes.values():      # повторный вход — резерв не удваиваем
                    n.reservations.pop(user, None)
                node = min(cands, key=lambda n: self.score(n, now))
                node.reservations[user] = now
                lines = []
                why = "новая сессия"
                if lost:
                    why += f"; прежняя сессия на недоступном узле {lost[0]['node']}"
            self.last_login[user] = {"node": node.host, "ip": ip, "time": now, "why": why}
        self.event("login", f"{user} → {node.host}: {why}", user=user, host=node.host, ip=ip)
        self.audit.write("broker.route", user, ip, "ok", node=node.host,
                         resume=bool(lines), reason=why)
        return node, lines, why

    # ---- действия администратора ----
    def set_drain(self, host, drained, who, ip=""):
        with self.lock:
            node = self.nodes.get(host)
            if not node:
                raise KeyError("узел не найден")
            node.drained = drained
            self._save_state()
        self.audit.write("node.drain" if drained else "node.undrain", who, ip, "ok", node=host)
        self.event("admin", f"{who}: узел {host} " +
                   ("выведен на обслуживание" if drained else "возвращён в работу"), host=host)

    def _session_owner(self, node, sid):
        with self.lock:
            for s in node.sessions:
                if s["sid"] == sid:
                    return s["user"]
        return ""

    def session_action(self, host, sid, action, who, ip=""):
        node = self.nodes.get(host)
        if not node:
            raise KeyError("узел не найден")
        if not SID_RE.match(sid):
            raise ValueError("некорректный идентификатор сессии")
        if action == "forget":
            # Узел недоступен: убираем сессию из учёта, чтобы она не мешала.
            with self.lock:
                if node.online:
                    raise ValueError("узел в строю — используйте «Завершить»")
                owner = self._session_owner(node, sid)
                node.sessions = [s for s in node.sessions if s["sid"] != sid]
            self.event("admin", f"{who}: сессия {sid} на {host} сброшена из учёта", host=host)
            self.audit.write("session.forget", who, ip, "ok", node=host, sid=sid, owner=owner)
            return {"ok": True}
        owner = self._session_owner(node, sid)
        try:
            res = self._ssh(node, f"{action} {sid}")
        except Exception as exc:
            self.audit.write(f"session.{action}", who, ip, "error", node=host, sid=sid,
                             owner=owner, error=str(exc)[:300])
            raise
        self.audit.write(f"session.{action}", who, ip, "ok" if res.get("ok") else "error",
                         node=host, sid=sid, owner=owner or res.get("user", ""),
                         forced=bool(res.get("forced")),
                         error=res.get("error") or ("" if res.get("ok") else res.get("detail", "")))
        self.event("admin", f"{who}: {action} {sid} на {host} → "
                   f"{'успешно' if res.get('ok') else res.get('error') or res.get('detail')}"
                   f"{' (принудительно)' if res.get('forced') else ''}", host=host)
        # Обновим картину узла сразу, не дожидаясь цикла опроса.
        self.pool.submit(self._refresh, node)
        return res

    def _refresh(self, node):
        node, data, err = self._poll_one(node)
        if data is not None:
            with self.lock:
                node.status = {k: v for k, v in data.items() if k != "sessions"}
                node.set_sessions([parse_session(l, node.host) for l in data["sessions"]])

    def client_event(self, user, params, ip):
        sid = params.get("sid", "")
        if not SID_RE.match(sid):
            return
        ev = {"user": user, "event": params.get("event", ""), "server": params.get("server", ""),
              "client": params.get("client", "") or ip, "os": params.get("os", ""),
              "version": params.get("version", ""), "time": time.time()}
        with self.lock:
            self.client_events[sid] = ev
            if len(self.client_events) > 5000:
                for k in list(self.client_events)[:1000]:
                    del self.client_events[k]

    def snapshot(self):
        now = time.time()
        ttl = self.bal["reserve_seconds"]
        with self.lock:
            nodes = [n.to_dict(now, ttl) for n in self.nodes.values()]
            sessions = []
            for n in self.nodes.values():
                for s in n.sessions:
                    d = {k: v for k, v in s.items() if k != "raw"}
                    d["node_online"] = n.online
                    ce = self.client_events.get(s["sid"])
                    if ce:
                        d["client_event"] = ce
                    sessions.append(d)
            events = list(self.events)[-200:]
            return {"now": now, "nodes": nodes, "sessions": sessions,
                    "events": events[::-1]}


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

def profiles_ini(cfg, user, first_host):
    out = []
    for p in cfg["profiles"]:
        out.append(f"[{p['id']}]")
        fields = {
            "name": p.get("name", p["id"]),
            "command": p.get("command", "MATE"),
            "host": first_host,          # фактический узел назначает selectsession
            "user": user,
            "usebrokerpass": "true",     # вход на узел тем же паролем, что и в брокер
        }
        fields.update({k: v for k, v in p.items() if k != "id"})
        for k, v in fields.items():
            if isinstance(v, bool):
                v = "true" if v else "false"
            v = str(v).replace("\n", " ")
            out.append(f"{k}={v}")
        out.append("")
    return "\n".join(out)


class Handler(BaseHTTPRequestHandler):
    server_version = "rrcki-x2gobroker"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # app присваивается при старте
    app = None

    def log_message(self, fmt, *args):  # тише стандартного журнала
        log.debug("%s %s", self.client_ip(), fmt % args)

    def client_ip(self):
        peer = self.client_address[0]
        if peer in self.app.cfg["broker"]["trusted_proxies"]:
            fwd = self.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[-1].strip()
        return peer

    def send(self, code, body, ctype="text/plain; charset=utf-8", extra=None, reason=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code, reason)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def read_body(self, limit=64 * 1024):
        n = int(self.headers.get("Content-Length") or 0)
        if n > limit:
            raise ValueError("слишком большой запрос")
        return self.rfile.read(n) if n else b""

    # ---- маршрутизация ----
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/admin", "/admin/"):
            return self.admin_page()
        if path == "/admin/api/state":
            return self.admin_state()
        if path == "/admin/api/audit":
            return self.admin_audit()
        if path == "/admin/api/audit.csv":
            return self.admin_audit_csv()
        if path == "/healthz":
            return self.send(200, "ok\n")
        return self.send(200, "rrcki-x2gobroker: используйте X2Go Client с --broker-url\n")

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self.read_body()
        except ValueError as exc:
            return self.send(413, str(exc))
        if path == "/admin/api/action":
            return self.admin_action(body)
        return self.broker_request(body)

    # ---- протокол X2Go Client ----
    def broker_request(self, body):
        params = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace"),
                                               keep_blank_values=True).items()}
        task = params.get("task", "")
        ip = self.client_ip()
        if task == "testcon":
            return self.send(200, "Access granted\n")
        user = normalize_user(params.get("user"))
        roles = self.app.auth.authenticate(user, params.get("password", ""), ip) if user else None
        if not roles or "user" not in roles:
            if roles is not None:
                log.info("Нет доступа (не в группе): %s", user)
                if task == "listsessions":
                    self.app.audit.write("access.denied", user, ip, "denied",
                                         channel="terminal", reason="нет в группе доступа к ферме")
            return self.send(200, "Access denied\n")
        farm = self.app.farm

        if task == "listsessions":
            first = next(iter(farm.nodes))
            body = ("Access granted\nSTART_USER_SESSIONS\n" +
                    profiles_ini(self.app.cfg, user, first) + "END_USER_SESSIONS\n")
            return self.send(200, body)

        if task == "selectsession":
            node, lines, why = farm.select(user, ip)
            if not node:
                farm.event("login", f"{user}: отказ — {why}", user=user, ip=ip, level="error")
                # Без строки SERVER клиент падает при разборе ответа, поэтому отвечаем
                # HTTP-ошибкой: X2Go Client покажет её текст (поясняющая фраза — только латиница).
                return self.send(503, f"{why}\n", reason="No free terminal servers, please try again later")
            out = f"Access granted\nSERVER:{node.host}:{node.ssh_port}\n"
            if lines:
                out += "SESSION_INFO:" + "\n".join(lines) + "\n"
            return self.send(200, out)

        if task == "clientevent":
            farm.client_event(user, params, ip)
            return self.send(200, "Access granted\n")

        if task == "setpass":
            return self.send(200, "Смена пароля через брокер не поддерживается. "
                                  "Смените пароль доменной учётной записи обычным способом.\n")
        return self.send(400, "unknown task\n")

    # ---- администрирование ----
    def send_json(self, obj, code=200):
        self.send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def panel_auth(self, need=None):
        """Вход в панель по Basic auth. -> (user, roles, perms) или None (ответ уже отправлен)."""
        ip = self.client_ip()
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                raw = base64.b64decode(hdr[6:]).decode("utf-8")
                login, _, pw = raw.partition(":")
            except Exception:  # noqa: BLE001
                login, pw = "", ""
            user = normalize_user(login)
            roles = self.app.auth.authenticate(user, pw, ip, "panel") if user else None
            if roles is not None:
                perms = perms_of(roles)
                if not perms:
                    self.app.audit.write("access.denied", user, ip, "denied", channel="panel",
                                         reason="нет роли панели")
                    self.send(403, "Нет ни одной роли панели (viewer, officer, admin, security)\n")
                    return None
                if need and need not in perms:
                    self.app.audit.write("access.denied", user, ip, "denied", channel="panel",
                                         reason=f"нет права {need}", path=urlparse(self.path).path)
                    self.send_json({"ok": False, "error": "недостаточно прав"}, 403)
                    return None
                return user, roles, perms
        self.send(401, "Требуется вход\n",
                  extra={"WWW-Authenticate": 'Basic realm="X2Go broker", charset="UTF-8"'})
        return None

    def admin_page(self):
        if not self.panel_auth("view"):
            return
        html = (HERE / "admin.html").read_bytes()
        self.send(200, html, "text/html; charset=utf-8",
                  extra={"Content-Security-Policy":
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
                         "X-Frame-Options": "DENY"})

    def admin_state(self):
        auth = self.panel_auth("view")
        if not auth:
            return
        who, roles, perms = auth
        snap = self.app.farm.snapshot()
        snap.update({"admin": who, "roles": sorted(r for r in roles if r in ROLE_PERMS),
                     "role_titles": ROLE_TITLES, "perms": sorted(perms)})
        self.send_json(snap)

    def admin_audit(self):
        if not self.panel_auth("audit"):
            return
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        try:
            limit = max(1, min(5000, int(q.get("limit", 500))))
        except ValueError:
            limit = 500
        audit = self.app.audit
        self.send_json({"records": audit.tail(limit, q.get("q", ""), q.get("event", "")),
                        "integrity": audit.verify(),
                        "lockouts": self.app.auth.lockouts(),
                        "lockout_seconds": self.app.cfg["auth"]["lockout_seconds"]})

    def admin_audit_csv(self):
        auth = self.panel_auth("audit")
        if not auth:
            return
        import csv
        import io
        q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
        recs = self.app.audit.tail(100000, q.get("q", ""), q.get("event", ""))
        self.app.audit.write("audit.export", auth[0], self.client_ip(), "ok",
                             records=len(recs), query=q.get("q", ""), event=q.get("event", ""))
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";")
        w.writerow(["время", "событие", "кто", "IP", "результат", "подробности", "хеш"])
        for r in reversed(recs):
            w.writerow([r["ts"], r["event"], r["actor"], r["ip"], r["result"],
                        _canon(r.get("details", {})), r.get("hash", "")])
        fname = f"x2go-audit-{datetime.date.today().isoformat()}.csv"
        # BOM — чтобы Excel открыл кириллицу без вопросов
        self.send(200, "\ufeff" + buf.getvalue(), "text/csv; charset=utf-8",
                  extra={"Content-Disposition": f'attachment; filename="{fname}"'})

    ACTION_PERMS = {"drain": "nodes", "undrain": "nodes", "suspend": "sessions",
                    "terminate": "sessions", "forget": "sessions", "unlock": "unlock"}

    def admin_action(self, body):
        try:
            req = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return self.send_json({"ok": False, "error": "некорректный запрос"}, 400)
        action = req.get("action")
        if action not in self.ACTION_PERMS:
            return self.send_json({"ok": False, "error": "неизвестное действие"}, 400)
        auth = self.panel_auth(self.ACTION_PERMS[action])
        if not auth:
            return
        who, ip = auth[0], self.client_ip()
        # Собственный заголовок нельзя отправить с чужого сайта без CORS — защита от CSRF.
        if self.headers.get("X-Broker-Admin") != "1":
            return self.send(403, "forbidden\n")
        host = req.get("host", "")
        farm = self.app.farm
        try:
            if action in ("drain", "undrain"):
                farm.set_drain(host, action == "drain", who, ip)
                res = {"ok": True}
            elif action == "unlock":
                key = req.get("key", "")
                self.app.auth.unlock(key)
                self.app.audit.write("security.unlock", who, ip, "ok", key=key)
                farm.event("security", f"{who}: снята блокировка {key}")
                res = {"ok": True}
            else:
                res = farm.session_action(host, req.get("sid", ""), action, who, ip)
        except (KeyError, ValueError) as exc:
            res = {"ok": False, "error": str(exc).strip("'\"")}
        except Exception as exc:  # noqa: BLE001
            log.exception("Ошибка действия в панели")
            res = {"ok": False, "error": str(exc)}
        self.send_json(res)


class App:
    def __init__(self, cfg):
        self.cfg = cfg
        self.audit = Audit(cfg["broker"]["audit_file"])
        self.auth = Authenticator(cfg["auth"], self.audit)
        self.farm = Farm(cfg, self.audit)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Лёгкий брокер сессий X2Go")
    ap.add_argument("-c", "--config", default="/etc/rrcki-x2gobroker/broker.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--check-login", metavar="USER",
                    help="проверить вход пользователя в AD и его группы, затем выйти")
    ap.add_argument("--check-nodes", action="store_true",
                    help="один раз опросить узлы, показать результат и выйти")
    ap.add_argument("--verify-audit", metavar="FILE", nargs="?", const="",
                    help="проверить цепочку хешей журнала аудита (по умолчанию из конфига)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    if args.verify_audit is not None:
        path = args.verify_audit or load_config(args.config)["broker"]["audit_file"]
        res = Audit.verify_file(path)
        if res["ok"]:
            print(f"{path}: цепочка цела, записей {res['records']}")
            return 0
        print(f"{path}: НАРУШЕНИЕ в строке {res['line']}: {res['error']} "
              f"(до неё проверено записей: {res['records']})")
        return 2
    cfg = load_config(args.config)
    app = App(cfg)

    if args.check_login:
        import getpass
        user = normalize_user(args.check_login)
        roles = app.auth.authenticate(user, getpass.getpass(f"Пароль {user}: "), "cli", "cli")
        if roles is None:
            print("Вход отклонён (неверный пароль или нет связи с AD — см. сообщения выше)")
            return 1
        panel = [f"{r} ({ROLE_TITLES[r]})" for r in PANEL_ROLES if r in roles]
        print(f"Пароль верный. Вход на ферму: {'да' if 'user' in roles else 'НЕТ'}; "
              f"роли панели: {', '.join(panel) or 'нет'}")
        return 0
    if args.check_nodes:
        app.farm.poll_once()
        for n in app.farm.nodes.values():
            state = "OK" if n.online else f"ОШИБКА: {n.last_error}"
            print(f"{n.host:30} {state:40} сессий: {len(n.sessions)}")
        return 0 if all(n.online for n in app.farm.nodes.values()) else 1
    Handler.app = app

    host, _, port = cfg["broker"]["listen"].rpartition(":")
    srv = ThreadingHTTPServer((host.strip("[]") or "127.0.0.1", int(port)), Handler)
    srv.daemon_threads = True

    poller = threading.Thread(target=app.farm.run_poller, name="poller", daemon=True)
    poller.start()
    app.audit.write("service.start", "system", "", "ok", nodes=len(app.farm.nodes),
                    roles={r: bool(g) for r, g in app.auth.role_groups.items()})
    log.info("Брокер слушает %s, узлов: %d", cfg["broker"]["listen"], len(app.farm.nodes))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.farm.stop()
        srv.server_close()


if __name__ == "__main__":
    sys.exit(main())
