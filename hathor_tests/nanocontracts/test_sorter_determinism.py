import os
import subprocess
import sys
from pathlib import Path


def run_in_subprocess(pythonhashseed: str) -> str:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = pythonhashseed

    # Add project root to PYTHONPATH so subprocess can import hathor
    current_dir = Path(__file__).parent
    project_root = current_dir.parent.parent  # Go up 2 levels to hathor-core root
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")

    script_path = current_dir / 'sorter_determinism.py'

    proc = subprocess.run(
        [sys.executable, script_path],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def test_algorithm_is_deterministic_across_pythonhashseed():
    results = set()
    for hseed in range(20):
        print('Running...', hseed)
        out = run_in_subprocess(str(hseed))
        results.add(out)
        assert len(results) == 1
