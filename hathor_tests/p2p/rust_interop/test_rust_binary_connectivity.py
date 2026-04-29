# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Real-socket p2p connectivity between a real Python ``HathorManager`` and the Rust port binary.

A full Python node (``run_node --testnet``) and the Rust ``htr-core`` binary talk over a real
TCP+TLS socket and complete the HELLO -> PEER-ID -> READY handshake. We assert the Python node's
status API reports the Rust peer in the ``READY`` state, for both connection directions.

Both sides use the predefined ``testnet-india`` network: its name and ``genesis_short_hash``
(``f7438fb``) match between the implementations with no custom config, and TLS works because the
Rust port embeds the same Hathor CA as ``hathorlib`` (so the certs are mutually trusted).

The suite is marked ``slow`` (it spawns subprocesses and a real reactor) and skips cleanly when the
Rust toolchain or binary is unavailable, so the default ``make tests`` stays green without Rust.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterator

import pytest

from hathorlib.conf import TESTNET_INDIA_SETTINGS_FILEPATH

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RUST_WORKSPACE = _REPO_ROOT / 'htr-rs'

# How long to wait for a node to come up / for the handshake to land.
_NODE_BOOT_TIMEOUT = 90.0
_HANDSHAKE_TIMEOUT = 40.0
# The Rust binary self-exits after this many seconds as a safety net if the test aborts.
_RUST_RUN_SECONDS = 60


def _find_rust_binary() -> str | None:
    """Locate the `htr-core` binary: `HTR_CORE_BIN`, then a prebuilt target binary.

    As a local convenience it builds the binary once if none is found, but never in CI — building a
    27MB Rust binary inside the Python test job is slow and out of place, so under `CI` the test
    simply skips unless a prebuilt binary or `HTR_CORE_BIN` is provided. Returns the path, or
    `None` when no binary is available.
    """
    override = os.environ.get('HTR_CORE_BIN')
    if override:
        return override if Path(override).exists() else None

    for profile in ('debug', 'release'):
        candidate = _RUST_WORKSPACE / 'target' / profile / 'htr-core'
        if candidate.exists():
            return str(candidate)

    if os.environ.get('CI') or not _RUST_WORKSPACE.exists():
        return None
    try:
        result = subprocess.run(
            ['cargo', 'build', '--bin', 'htr-core'],
            cwd=_RUST_WORKSPACE,
            capture_output=True,
        )
    except FileNotFoundError:
        return None  # cargo not installed
    if result.returncode != 0:
        return None
    built = _RUST_WORKSPACE / 'target' / 'debug' / 'htr-core'
    return str(built) if built.exists() else None


@pytest.fixture(scope='module')
def rust_binary() -> str:
    binary = _find_rust_binary()
    if binary is None:
        pytest.skip(
            'htr-core binary unavailable; build it (cargo build --bin htr-core) or set '
            'HTR_CORE_BIN. Not auto-built under CI.'
        )
    return binary


def _status_url(status_port: int) -> str:
    return f'http://127.0.0.1:{status_port}/v1a/status/'


def _http_get_json(url: str, timeout: float = 2.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        result: dict[str, Any] = json.loads(resp.read())
        return result


def _spawn_python_node(*, listen: int, status: int, bootstrap: str | None) -> subprocess.Popen[bytes]:
    """Start a real testnet-india full node, restricted to localhost so it never touches the real
    network. Waits until its status API answers."""
    command = [
        'python', '-m', 'hathor', 'run_node', '--testnet', '--temp-data', '--wallet', 'hd',
        '--allow-mining-without-peers', '--x-localhost-only',
        '--hostname', '127.0.0.1', '--listen', f'tcp:{listen}', '--status', str(status),
    ]
    if bootstrap is not None:
        command += ['--bootstrap', bootstrap]

    # The test session sets HATHOR_CONFIG_YAML to the unittests network (see hathor_tests/conftest.py),
    # which the child would otherwise inherit — putting it on a different genesis than the Rust node
    # and breaking the HELLO handshake. Force testnet-india to match the Rust `--testnet-india`.
    child_env = dict(os.environ)
    child_env['HATHOR_CONFIG_YAML'] = TESTNET_INDIA_SETTINGS_FILEPATH
    process = subprocess.Popen(command, env=child_env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + _NODE_BOOT_TIMEOUT
    while True:
        if process.poll() is not None:
            raise RuntimeError(f'python node exited early with code {process.returncode}')
        try:
            _http_get_json(_status_url(status))
            return process
        except Exception:
            if time.time() > deadline:
                process.terminate()
                raise TimeoutError('python node did not start in time')
            time.sleep(0.3)


def _spawn_rust_node(binary: str, *, listen: int | None = None,
                     connect: int | None = None) -> subprocess.Popen[bytes]:
    command = [binary, '--testnet-india', '--timeout', str(_RUST_RUN_SECONDS)]
    if listen is not None:
        command += ['--listen', f'tcp://127.0.0.1:{listen}']
    if connect is not None:
        command += ['--connect', f'tcp://127.0.0.1:{connect}']
    return subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _wait_for_ready_peer(status_port: int) -> dict[str, Any]:
    """Poll the Python node's status API until a peer reaches READY; return that peer entry."""
    deadline = time.time() + _HANDSHAKE_TIMEOUT
    last_seen: list[dict[str, Any]] = []
    while time.time() < deadline:
        try:
            status = _http_get_json(_status_url(status_port))
        except Exception:
            time.sleep(0.3)
            continue
        last_seen = status.get('connections', {}).get('connected_peers', [])
        for peer in last_seen:
            if peer.get('state') == 'READY':
                return peer
        time.sleep(0.3)
    raise AssertionError(f'no peer reached READY; last connected_peers={last_seen}')


@pytest.fixture
def terminator() -> Iterator[list[subprocess.Popen[bytes]]]:
    procs: list[subprocess.Popen[bytes]] = []
    try:
        yield procs
    finally:
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=10)
            except Exception:
                proc.kill()


@pytest.mark.slow
def test_rust_connects_to_python_node(rust_binary: str, terminator: list[subprocess.Popen[bytes]]) -> None:
    """Rust dials a listening Python node; the Python node must report it as a READY peer."""
    py_listen, py_status = 8120, 8220
    python_node = _spawn_python_node(listen=py_listen, status=py_status, bootstrap=None)
    terminator.append(python_node)

    rust_node = _spawn_rust_node(rust_binary, connect=py_listen)
    terminator.append(rust_node)

    peer = _wait_for_ready_peer(py_status)
    assert peer['state'] == 'READY'
    assert peer['app_version'].startswith('Hathor-experimental')


@pytest.mark.slow
def test_python_node_connects_to_rust(rust_binary: str, terminator: list[subprocess.Popen[bytes]]) -> None:
    """Python dials a listening Rust node; the Python node must report it as a READY peer."""
    rust_listen = 8121
    py_listen, py_status = 8122, 8222

    rust_node = _spawn_rust_node(rust_binary, listen=rust_listen)
    terminator.append(rust_node)
    # Give the Rust listener a moment to bind before the Python node bootstraps to it.
    time.sleep(1.0)

    bootstrap = f'tcp://127.0.0.1:{rust_listen}'
    python_node = _spawn_python_node(listen=py_listen, status=py_status, bootstrap=bootstrap)
    terminator.append(python_node)

    peer = _wait_for_ready_peer(py_status)
    assert peer['state'] == 'READY'
    assert peer['app_version'].startswith('Hathor-experimental')
