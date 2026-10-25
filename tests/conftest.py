"""Build tiny synthetic PEX files so tests are fast, offline and deterministic.

They mimic the layout pex writes: PEX-INFO, .bootstrap/, and .deps/<wheel-name>/...
(or .deps/<wheel-name> as a zip for --no-pre-install-wheels).
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest


def _metadata(name: str, version: str, requires=(), license=None) -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    if license:
        lines.append(f"License-Expression: {license}")
    lines += [f"Requires-Dist: {r}" for r in requires]
    return "\n".join(lines) + "\n\n"


def _dist_files(wheel: str, requires, license, payload: int) -> dict[str, bytes]:
    name, version = wheel.split("-")[:2]
    info = f"{name}-{version}.dist-info"
    return {
        f"{info}/METADATA": _metadata(name, version, requires, license).encode(),
        f"{info}/WHEEL": b"Wheel-Version: 1.0\n",
        f"{name}/__init__.py": b"x" * payload,
    }


@pytest.fixture
def make_pex(tmp_path: Path):
    """make_pex("name.pex", dists=[(wheel_filename, requires, license, payload_bytes)], ...)"""

    def _make(
        filename: str,
        dists,
        requirements=(),
        wheel_files: bool = False,
        directory: bool = False,
        interpreter_constraints=(),
        code_hash="da39a3ee5e6b4b0d3255bfef95601890afd80709",
    ) -> Path:
        info = {
            "build_properties": {"pex_version": "2.105.1"},
            "code_hash": code_hash,
            "deps_are_wheel_files": wheel_files,
            "distributions": {d[0]: f"sha-{d[0]}" for d in dists},
            "interpreter_constraints": list(interpreter_constraints),
            "requirements": list(requirements),
        }
        files: dict[str, bytes] = {
            "PEX-INFO": json.dumps(info).encode(),
            "__main__.py": b"# bootstrap\n",
            ".bootstrap/pex/__init__.py": b"#" * 500,
        }
        for wheel, requires, license, payload in dists:
            inner = _dist_files(wheel, requires, license, payload)
            if wheel_files:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    for k, v in inner.items():
                        zf.writestr(k, v)
                files[f".deps/{wheel}"] = buf.getvalue()
            else:
                for k, v in inner.items():
                    files[f".deps/{wheel}/{k}"] = v

        out = tmp_path / filename
        if directory:
            for k, v in files.items():
                p = out / k
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(v)
        else:
            with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
                for k, v in files.items():
                    zf.writestr(k, v)
        return out

    return _make
