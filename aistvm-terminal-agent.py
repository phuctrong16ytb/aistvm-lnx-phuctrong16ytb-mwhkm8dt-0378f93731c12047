#!/usr/bin/env python3
# AISTVM Linux terminal agent. Standard library only.
# Serves a persistent PTY shell and resource metrics over the Tailscale interface.
import base64
import errno
import fcntl
import hmac
import json
import os
import pty
import select
import struct
import subprocess
import termios
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("AISTVM_TERMINAL_PORT", "8790"))
TOKEN = os.environ.get("AISTVM_TERMINAL_TOKEN", "")
LINUX_USER = os.environ.get("AISTVM_LINUX_USER", "")
WORKSPACE = os.environ.get("AISTVM_WORKSPACE", "/tmp/aistvm-workspace")
SHELL = os.environ.get("AISTVM_SHELL", "/bin/bash")
MAX_INPUT = 8192
MAX_BUFFER = 262144
READ_TIMEOUT = 20.0
READ_LIMIT = 32768
DEFAULT_COLS = 80
DEFAULT_ROWS = 24


def _cpu_sample():
    with open("/proc/stat", "r", encoding="utf-8") as handle:
        first = handle.readline().split()
    values = [int(part) for part in first[1:]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return idle, sum(values)


def _memory():
    total = available = 0
    with open("/proc/meminfo", "r", encoding="utf-8") as handle:
        for line in handle:
            if line.startswith("MemTotal:"):
                total = int(line.split()[1]) * 1024
            elif line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
    used = total - available
    percent = (used / total * 100.0) if total > 0 else 0.0
    return used, total, percent


def metrics_payload(previous):
    idle, total = _cpu_sample()
    cpu = 0.0
    if previous is not None:
        idle_delta = idle - previous[0]
        total_delta = total - previous[1]
        if total_delta > 0:
            cpu = max(0.0, min(100.0, (total_delta - idle_delta) * 100.0 / total_delta))
    used, total_mem, percent = _memory()
    with open("/proc/uptime", "r", encoding="utf-8") as handle:
        uptime = float(handle.read().split()[0])
    return (idle, total), {
        "cpu_percent": round(cpu, 1),
        "ram_percent": round(percent, 1),
        "ram_used_gb": round(used / 1073741824.0, 2),
        "ram_total_gb": round(total_mem / 1073741824.0, 2),
        "uptime_seconds": round(uptime, 1),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


class ShellSession:
    """One persistent PTY plus a bounded, offset-addressed output ring."""

    def __init__(self):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
        self.master = None
        self.process = None
        self.buffer = bytearray()
        self.start_offset = 0
        self.total = 0
        self.reader = None
        self.stopped = False

    @property
    def running(self):
        return self.master is not None and not self.stopped

    def start(self, cols, rows):
        with self.lock:
            if self.running:
                self._resize_locked(cols, rows)
                return
            master, slave = pty.openpty()
            self._set_winsize(master, cols, rows)
            env = dict(os.environ)
            env["TERM"] = "xterm-256color"
            env["COLORTERM"] = "truecolor"
            env["LANG"] = env.get("LANG", "C.UTF-8")
            env["AISTVM_SHELL"] = SHELL
            kwargs = {
                "stdin": slave,
                "stdout": slave,
                "stderr": slave,
                "cwd": WORKSPACE,
                "env": env,
                "close_fds": True,
                # A new session plus the PTY makes the shell a controlling
                # terminal, which is what gives it job control and lets Ctrl-C
                # reach the foreground process.
                "start_new_session": True,
            }
            if LINUX_USER:
                # The agent runs as root; hand the shell to the session user.
                kwargs["user"] = LINUX_USER
                kwargs["group"] = LINUX_USER
                kwargs["extra_groups"] = []
            try:
                process = subprocess.Popen([SHELL, "-l"], **kwargs)
            except (OSError, ValueError):
                os.close(master)
                os.close(slave)
                raise
            os.close(slave)
            self.process = process
            self.master = master
            self.buffer = bytearray()
            self.start_offset = 0
            self.total = 0
            self.stopped = False
            self.reader = threading.Thread(target=self._pump, daemon=True)
            self.reader.start()

    def _set_winsize(self, fd, cols, rows):
        packed = struct.pack("HHHH", max(1, rows), max(1, cols), 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, packed)

    def _resize_locked(self, cols, rows):
        if self.master is None:
            return
        try:
            self._set_winsize(self.master, cols, rows)
        except OSError:
            pass

    def resize(self, cols, rows):
        with self.lock:
            self._resize_locked(cols, rows)

    def write(self, data):
        with self.lock:
            if not self.running:
                return False
            try:
                os.write(self.master, data)
                return True
            except OSError:
                return False

    def _pump(self):
        master = self.master
        while True:
            try:
                ready, _, _ = select.select([master], [], [], 0.5)
            except (OSError, ValueError):
                break
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    break
                if not chunk:
                    break
                with self.lock:
                    self.buffer.extend(chunk)
                    self.total += len(chunk)
                    overflow = len(self.buffer) - MAX_BUFFER
                    if overflow > 0:
                        del self.buffer[:overflow]
                        self.start_offset += overflow
                    self.condition.notify_all()
            if self.stopped:
                break
        with self.lock:
            self.stopped = True
            self.condition.notify_all()

    def read(self, offset):
        with self.lock:
            if offset < self.start_offset:
                offset = self.start_offset
            index = offset - self.start_offset
            if index < 0:
                index = 0
            deadline = time.monotonic() + READ_TIMEOUT
            while index >= len(self.buffer) and not self.stopped:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(remaining)
            data = bytes(self.buffer[index:index + READ_LIMIT])
            return {
                "data": base64.b64encode(data).decode("ascii"),
                "offset": offset + len(data),
                "start_offset": self.start_offset,
                "running": self.running,
            }

    def close(self):
        with self.lock:
            self.stopped = True
            process = self.process
            self.process = None
            master = self.master
            self.master = None
            self.condition.notify_all()
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except Exception:
                pass

    def status(self):
        with self.lock:
            return {
                "running": self.running,
                "offset": self.total,
                "start_offset": self.start_offset,
            }


SESSION = ShellSession()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last_sample = None

    def log_message(self, *args):
        # Never write request lines or headers: the token travels in a header.
        return

    def _authorized(self):
        if not TOKEN:
            # Without a configured token nothing is authorized.
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].strip(), TOKEN)

    def _send(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_INPUT * 8:
            return None
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _query(self, name, default):
        if "?" not in self.path:
            return default
        from urllib.parse import parse_qs, urlparse

        values = parse_qs(urlparse(self.path).query).get(name)
        if not values:
            return default
        try:
            return int(values[0])
        except ValueError:
            return default

    def _path(self):
        return self.path.split("?", 1)[0]

    def do_GET(self):
        path = self._path()
        if path == "/health":
            self._send(200, {"ok": True})
            return
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        if path == "/metrics":
            sample, payload = metrics_payload(Handler.last_sample)
            Handler.last_sample = sample
            self._send(200, payload)
            return
        if path == "/shell/read":
            offset = max(0, self._query("offset", 0))
            self._send(200, SESSION.read(offset))
            return
        if path == "/shell/status":
            self._send(200, SESSION.status())
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        path = self._path()
        if path == "/shell/open":
            body = self._read_json() or {}
            cols = body.get("cols", DEFAULT_COLS)
            rows = body.get("rows", DEFAULT_ROWS)
            if not isinstance(cols, int) or not 2 <= cols <= 1000:
                cols = DEFAULT_COLS
            if not isinstance(rows, int) or not 1 <= rows <= 1000:
                rows = DEFAULT_ROWS
            SESSION.start(cols, rows)
            self._send(200, SESSION.status())
            return
        if path == "/shell/input":
            body = self._read_json()
            if not body or not isinstance(body.get("data"), str):
                self._send(400, {"error": "invalid body"})
                return
            try:
                raw = base64.b64decode(body["data"], validate=True)
            except (ValueError, TypeError):
                self._send(400, {"error": "invalid base64"})
                return
            if len(raw) > MAX_INPUT:
                self._send(400, {"error": "input too large"})
                return
            ok = SESSION.write(raw)
            self._send(200, {"ok": ok, "running": SESSION.running})
            return
        if path == "/shell/resize":
            body = self._read_json() or {}
            cols = body.get("cols")
            rows = body.get("rows")
            if isinstance(cols, int) and isinstance(rows, int):
                SESSION.resize(cols, rows)
            self._send(200, SESSION.status())
            return
        if path == "/shell/close":
            SESSION.close()
            self._send(200, SESSION.status())
            return
        self._send(404, {"error": "not found"})


def main():
    os.makedirs(WORKSPACE, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("AISTVM terminal agent listening on port " + str(PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SESSION.close()


if __name__ == "__main__":
    main()
