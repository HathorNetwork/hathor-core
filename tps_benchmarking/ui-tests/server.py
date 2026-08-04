"""Local UI server for the TPS benchmark — proof of concept.

Stdlib only (no flask/fastapi in the venv, and this is a throwaway POC — no new deps). Each
simulation runs as a SUBPROCESS of run_sim.py, which streams newline-delimited JSON progress on
stdout; a reader thread folds those events into in-memory run state that the browser polls.

    poetry run python tps_benchmarking/ui-tests/server.py [--port 8765] [--no-browser]

Routes
    GET  /                      the app shell
    GET  /static/<f>            css / js
    GET  /api/simulations       the declarative form spec (simulations.py)
    POST /api/run               {sim_id, params} -> {run_id}
    GET  /api/run/<run_id>      status, progress, results
    GET  /runs/<ts>/<file>      produced artifacts (png / xlsx / json)

Scope: single user, localhost, no auth, state in memory. Not a pipeline component.
"""
from __future__ import annotations

import argparse
import errno
import json
import subprocess
import sys
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from simulations import BY_ID, SIMULATIONS, defaults  # noqa: E402

RUNS: dict[str, dict] = {}
RUNS_LOCK = threading.Lock()
SENTINEL = "@@TPSUI@@"      # must match run_sim.py — hathor logs to stdout alongside the protocol
LOG_TAIL = 500              # node output lines kept per run (ring buffer feeding the console)
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "text/javascript; charset=utf-8", ".png": "image/png", ".json": "application/json",
        ".svg": "image/svg+xml", ".pdf": "application/pdf",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}


def _set(run_id: str, **kw) -> None:
    with RUNS_LOCK:
        RUNS[run_id].update(kw)


def _pump(run_id: str, proc: subprocess.Popen) -> None:
    """Fold the worker's sentinel-prefixed JSONL events into run state until it exits.

    Anything without the sentinel is the node's own stdout logging: kept as a bounded tail so a
    crash can be diagnosed, never parsed as protocol."""
    assert proc.stdout is not None
    # iter(readline) rather than `for line in proc.stdout`: iterating a pipe uses a hidden
    # read-ahead buffer, which holds every event back until the child exits — progress would only
    # appear once the run was already over.
    for line in iter(proc.stdout.readline, ""):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if not line.startswith(SENTINEL):
            with RUNS_LOCK:
                run = RUNS[run_id]
                run["log"].append(line[:600])
                # Ring buffer: remember how many lines fell off the front so /log can tell a
                # client whether it missed any rather than silently renumbering.
                if len(run["log"]) > LOG_TAIL:
                    dropped = len(run["log"]) - LOG_TAIL
                    del run["log"][:dropped]
                    run["log_dropped"] += dropped
            continue
        try:
            ev = json.loads(line[len(SENTINEL):])
        except ValueError:
            continue
        kind = ev.get("t")
        # Carry the cell/repetition context through verbatim — without this the worker emits it and
        # the server silently drops it, so the UI can never say which cell or rep is running.
        extra = {k: ev[k] for k in ("cell", "cell_index", "cells", "rep", "reps") if k in ev}
        if kind == "phase":
            _set(run_id, phase=ev["phase"], message=ev.get("msg", ""), done=0, total=0, **extra)
        elif kind == "progress":
            _set(run_id, phase=ev["phase"], done=ev["done"], total=ev["total"], **extra)
        elif kind == "done":
            _set(run_id, status="done", phase="done", message="complete",
                 result={k: v for k, v in ev.items() if k != "t"})
        elif kind == "error":
            _set(run_id, status="error", phase="error",
                 message=ev.get("msg", "failed"), trace=ev.get("trace", ""))
    proc.wait()
    with RUNS_LOCK:
        if RUNS[run_id]["status"] == "running":      # exited without a done/error event
            RUNS[run_id].update(status="error", phase="error",
                                message=f"worker exited with code {proc.returncode}",
                                trace="\n".join(RUNS[run_id]["log"][-20:])
                                      or "no output captured")


def start_run(sim_id: str, params: dict) -> str:
    sim = BY_ID[sim_id]
    merged = defaults(sim_id)
    merged.update({k: v for k, v in params.items() if k in merged})
    merged["sim_id"] = sim_id
    # setdefault, NOT update: the Custom card carries a `workload` CONTROL, and overwriting it with
    # the card's static field silently forced every Custom run to 1-tip-transparent regardless of
    # the dropdown. Scenario cards have no such control, so they still pick up their own workload.
    merged.setdefault("workload", sim["workload"])

    run_id = uuid.uuid4().hex[:12]
    merged["run_id"] = run_id          # the worker folds this into its output dir name (uniqueness)
    with RUNS_LOCK:
        RUNS[run_id] = {"run_id": run_id, "sim_id": sim_id, "params": merged, "status": "running",
                        "phase": "boot", "message": "starting…", "done": 0, "total": 0,
                        "cell": None, "cell_index": 0, "cells": sim.get("cells", 1),
                        "rep": 1, "reps": int(merged.get("k", 1) or 1),
                        "result": None, "trace": "", "log": [], "log_dropped": 0}
    proc = subprocess.Popen(
        [sys.executable, str(HERE / "run_sim.py"), json.dumps(merged)],
        # stderr folded into stdout so a traceback reaches the console panel too; it cannot be
        # confused with protocol output, which is sentinel-prefixed.
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=str(HERE))
    threading.Thread(target=_pump, args=(run_id, proc), daemon=True).start()
    return run_id


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):          # quiet: the console is for run progress
        pass

    # ---- helpers ----------------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _file(self, path: Path, root: Path) -> None:
        """Serve a file, refusing anything that escapes `root` (path-traversal guard)."""
        try:
            resolved = path.resolve()
            resolved.relative_to(root.resolve())
        except (ValueError, OSError):
            return self._json({"error": "forbidden"}, 403)
        if not resolved.is_file():
            return self._json({"error": "not found"}, 404)
        self._send(200, resolved.read_bytes(), MIME.get(resolved.suffix, "application/octet-stream"))

    def _log(self, run_id: str, query: str) -> None:
        """Incremental node output: `?since=N` returns only lines after absolute index N.

        Absolute indices survive the ring buffer, so a client that falls behind is told how many
        lines it missed instead of being handed a silently renumbered window."""
        since = 0
        for part in (query or "").split("&"):
            if part.startswith("since="):
                try:
                    since = max(0, int(part[6:]))
                except ValueError:
                    since = 0
        with RUNS_LOCK:
            run = RUNS.get(run_id)
            if run is None:
                return self._json({"error": "unknown run"}, 404)
            dropped, lines = run["log_dropped"], list(run["log"])
            running = run["status"] == "running"
        start = max(since, dropped)                     # can't serve what the buffer discarded
        return self._json({"lines": lines[start - dropped:], "next": dropped + len(lines),
                           "missed": max(0, dropped - since), "running": running})

    # ---- routes -----------------------------------------------------------------
    def do_GET(self) -> None:
        route = unquote(urlparse(self.path).path)
        if route == "/":
            return self._file(HERE / "static" / "index.html", HERE / "static")
        if route.startswith("/static/"):
            return self._file(HERE / "static" / route[len("/static/"):], HERE / "static")
        if route.startswith("/runs/"):
            return self._file(HERE / "runs" / route[len("/runs/"):], HERE / "runs")
        if route == "/api/simulations":
            return self._json({"simulations": SIMULATIONS})
        if route.startswith("/api/run/"):
            rest = route[len("/api/run/"):]
            if rest.endswith("/log"):
                return self._log(rest[: -len("/log")], urlparse(self.path).query)
            with RUNS_LOCK:
                run = RUNS.get(rest)
                payload = dict(run) if run else None
            if payload is None:
                return self._json({"error": "unknown run"}, 404)
            payload.pop("log", None)          # streamed separately via /log, not on every poll
            payload.pop("log_dropped", None)
            return self._json(payload)
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        route = unquote(urlparse(self.path).path)
        if route != "/api/run":
            return self._json({"error": "not found"}, 404)
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        sim_id = body.get("sim_id")
        if sim_id not in BY_ID:
            return self._json({"error": f"unknown simulation {sim_id!r}"}, 400)
        try:
            run_id = start_run(sim_id, body.get("params") or {})
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"{type(e).__name__}: {e}"}, 500)
        print(f"  [run {run_id}] {sim_id} started")
        self._json({"run_id": run_id})


def main() -> int:
    ap = argparse.ArgumentParser(description="TPS benchmark UI (proof of concept)")
    ap.add_argument("--port", type=int, default=8765)
    # 0.0.0.0, not 127.0.0.1: under WSL2 the browser runs on the Windows host, and a loopback-only
    # bind is reachable only through WSL's localhost forwarding — which is often off. Binding all
    # interfaces makes both http://localhost:PORT and http://<wsl-ip>:PORT work. Pass
    # --host 127.0.0.1 to restrict it again.
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()

    (HERE / "runs").mkdir(exist_ok=True)
    url = f"http://{args.host}:{args.port}/"
    ThreadingHTTPServer.allow_reuse_address = True
    ThreadingHTTPServer.request_queue_size = 64   # HTTP/1.1 keep-alive: a browser holds several
    try:
        srv = ThreadingHTTPServer((args.host, args.port), Handler)
    except OSError as e:
        if e.errno != errno.EADDRINUSE:
            raise
        print(f"port {args.port} is already in use — start on another one, e.g.\n"
              f"  python {Path(__file__).name} --port {args.port + 1}", file=sys.stderr)
        return 2
    print(f"TPS benchmark UI  →  {url}\n  runs land in {HERE / 'runs'}\n  Ctrl-C to stop\n")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
