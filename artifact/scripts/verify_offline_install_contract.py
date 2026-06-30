#!/usr/bin/env python3
"""Verify that the artifact package installs without build-time network access."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _venv_python(environment: Path) -> Path:
    if os.name == "nt":
        return environment / "Scripts" / "python.exe"
    return environment / "bin" / "python"


def _run(command: list[str], cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    print(result.stdout, end="")
    return result


def main() -> int:
    report: dict[str, object]
    with tempfile.TemporaryDirectory(prefix="repairwitness-offline-install-") as temporary:
        environment = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = _venv_python(environment)
        install = _run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                ".",
            ]
        )
        if install.returncode == 0:
            probe = _run(
                [
                    str(python),
                    "-c",
                    (
                        "import importlib.metadata as m; "
                        "import repairwitness; "
                        "print(m.version('repairwitness')); "
                        "print(repairwitness.__name__)"
                    ),
                ]
            )
        else:
            probe = subprocess.CompletedProcess([], 1, "")
        report = {
            "schema_version": 1,
            "kind": "OFFLINE_INSTALL_CONTRACT",
            "status": "PASS" if install.returncode == 0 and probe.returncode == 0 else "FAIL",
            "python": sys.version.split()[0],
            "pip_command": "python -m pip install --no-index --no-deps .",
            "install_returncode": install.returncode,
            "probe_returncode": probe.returncode,
            "install_output_tail": install.stdout[-2000:],
            "probe_output_tail": probe.stdout[-1000:],
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    print("REPAIRWITNESS_OFFLINE_INSTALL=" + str(report["status"]))
    return 0 if report["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
