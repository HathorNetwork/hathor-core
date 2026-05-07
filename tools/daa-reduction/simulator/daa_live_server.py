#!/usr/bin/env python3
"""
Web server for live DAA transition simulation dashboard.

Spawns the simulation script as a subprocess and streams its JSONL output
to the browser via Server-Sent Events (SSE).

Usage:
    poetry run python tools/daa-reduction/simulator/daa_live_server.py
"""
from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse

PORT = 8765
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RUNS_DIR = os.path.join(SCRIPT_DIR, 'daa_runs')
os.makedirs(RUNS_DIR, exist_ok=True)


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler for the DAA simulation dashboard."""

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == '/':
            self._serve_file('daa_live_dashboard.html', 'text/html')
        elif parsed.path == '/run':
            params = urllib.parse.parse_qs(parsed.query)
            self._stream_simulation(params)
        elif parsed.path == '/runs':
            self._list_runs()
        elif parsed.path.startswith('/runs/'):
            run_id = parsed.path[6:]
            self._get_run(run_id)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == '/runs':
            content_length = int(self.headers['Content-Length'])
            body = json.loads(self.rfile.read(content_length))
            run_id = body.get('run_id', f'run_{int(time.time())}')
            filepath = os.path.join(RUNS_DIR, f'{run_id}.json')
            with open(filepath, 'w') as f:
                json.dump(body, f)
            self.send_response(201)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'saved': run_id}).encode())
        elif parsed.path.startswith('/runs/') and parsed.path.endswith('/delete'):
            run_id = parsed.path[6:-7]
            filepath = os.path.join(RUNS_DIR, f'{run_id}.json')
            if os.path.isfile(filepath):
                os.remove(filepath)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'deleted': run_id}).encode())
            else:
                self.send_error(404)
        else:
            self.send_error(404)

    def _serve_file(self, filename: str, content_type: str) -> None:
        filepath = os.path.join(SCRIPT_DIR, filename)
        if not os.path.isfile(filepath):
            self.send_error(404, f'File not found: {filename}')
            return
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.end_headers()
        with open(filepath, 'rb') as f:
            self.wfile.write(f.read())

    def _stream_simulation(self, params: dict) -> None:
        """Spawn simulation subprocess and stream JSONL output as SSE."""
        import datetime

        cmd = [
            'poetry', 'run', 'python',
            os.path.join(SCRIPT_DIR, 'daa_transition_simulation.py'),
            '--jsonl',
        ]
        for key in ('hashpower', 'seed', 'total_blocks', 'eval_interval'):
            if key in params:
                cli_key = key.replace('_', '-')
                cmd += [f'--{cli_key}', params[key][0]]

        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'keep-alive')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        blocks: list[dict] = []
        run_meta: dict = {}
        run_config: dict = {}

        started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        t0 = time.time()

        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.dirname(SCRIPT_DIR))),  # project root
            env=env,
        )

        # Drain stderr in a background thread to prevent deadlock.
        # Forward to server's stderr so errors are visible in the terminal.
        stderr_lines: list[str] = []

        def _drain_stderr() -> None:
            assert proc.stderr is not None
            for line in proc.stderr:
                stderr_lines.append(line)
                sys.stderr.write(line)
                sys.stderr.flush()

        stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
        stderr_thread.start()

        try:
            assert proc.stdout is not None
            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                self.wfile.write(f'data: {line}\n\n'.encode())
                self.wfile.flush()

                try:
                    event = json.loads(line)
                    if event.get('type') == 'block':
                        blocks.append(event)
                    elif event.get('type') == 'config':
                        run_config = event
                    elif event.get('type') == 'run_start':
                        run_meta = event
                    elif event.get('type') == 'run_end':
                        run_meta['summary'] = event.get('summary', {})
                        run_meta['started_at'] = event.get('started_at', started_at)
                        run_meta['duration_seconds'] = event.get(
                            'duration_seconds', round(time.time() - t0, 1)
                        )
                except json.JSONDecodeError:
                    pass
        except BrokenPipeError:
            proc.kill()
        finally:
            proc.wait()
            stderr_thread.join(timeout=5)

        # If simulation crashed, send stderr as an error event
        if proc.returncode != 0 and stderr_lines:
            error_msg = ''.join(stderr_lines[-20:])  # last 20 lines
            error_event = json.dumps({'type': 'error', 'message': error_msg})
            try:
                self.wfile.write(f'data: {error_event}\n\n'.encode())
                self.wfile.flush()
            except BrokenPipeError:
                pass

        # Auto-save completed run
        if blocks and run_meta:
            run_id = run_meta.get('run_id', f'run_{int(time.time())}')
            save_path = os.path.join(RUNS_DIR, f'{run_id}.json')
            with open(save_path, 'w') as f:
                json.dump({
                    'meta': run_meta,
                    'config': run_config,
                    'blocks': blocks,
                    'started_at': run_meta.get('started_at', started_at),
                    'duration_seconds': run_meta.get(
                        'duration_seconds', round(time.time() - t0, 1)
                    ),
                }, f)

    def _list_runs(self) -> None:
        """Return list of saved run files."""
        runs = []
        if os.path.isdir(RUNS_DIR):
            for fname in sorted(os.listdir(RUNS_DIR)):
                if not fname.endswith('.json'):
                    continue
                filepath = os.path.join(RUNS_DIR, fname)
                try:
                    with open(filepath) as f:
                        data = json.load(f)
                    runs.append({
                        'run_id': fname[:-5],
                        'meta': data.get('meta', {}),
                        'block_count': len(data.get('blocks', [])),
                    })
                except (json.JSONDecodeError, OSError):
                    pass
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(runs).encode())

    def _get_run(self, run_id: str) -> None:
        """Return full data for a saved run."""
        filepath = os.path.join(RUNS_DIR, f'{run_id}.json')
        if not os.path.isfile(filepath):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        with open(filepath, 'rb') as f:
            self.wfile.write(f.read())

    def log_message(self, format: str, *args: object) -> None:
        """Suppress per-request logging."""
        pass


def main() -> None:
    server = http.server.HTTPServer(('0.0.0.0', PORT), DashboardHandler)
    print(f'DAA Transition Dashboard: http://0.0.0.0:{PORT}')

    try:
        import webbrowser
        webbrowser.open(f'http://localhost:{PORT}')
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()


if __name__ == '__main__':
    main()
