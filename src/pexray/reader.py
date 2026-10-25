"""Read a PEX without executing it.

A PEX is either a zip file or a directory (``--layout packed|loose``). Either way it
has a ``PEX-INFO`` JSON file and a ``.deps/`` tree holding one entry per bundled
distribution, named after the original wheel file. Each entry is one of:

* a directory of installed files      (zip PEX, default ``deps_are_wheel_files: false``;
                                        loose directory layout)
* a single zip file                    (``--no-pre-install-wheels``: the original .whl;
                                        packed layout: a zipped install chroot)

We only read the zip index and a few small metadata files, so a 1 GB PEX opens fast,
and a PEX built for another OS or architecture reads just as well.
"""

from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass, field
from email.parser import Parser
from pathlib import Path, PurePosixPath

from packaging.requirements import InvalidRequirement, Requirement
from packaging.tags import Tag
from packaging.utils import (
    InvalidWheelFilename,
    NormalizedName,
    canonicalize_name,
    parse_wheel_filename,
)

DEPS_DIR = ".deps"
EMPTY_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"


class PexReadError(Exception):
    """The path is not a PEX we can read."""


@dataclass(frozen=True)
class Dist:
    """One distribution bundled in a PEX."""

    filename: str  # original wheel file name, e.g. numpy-2.1.2-cp312-cp312-....whl
    project: NormalizedName
    display_name: str  # name as written in METADATA (or the wheel file name)
    version: str
    tags: frozenset[Tag]
    stored_bytes: int  # bytes this dist occupies inside the PEX (compressed)
    installed_bytes: int  # uncompressed size of its files
    file_count: int
    requires: tuple[Requirement, ...] = ()
    license: str | None = None
    sha256: str | None = None  # hash recorded in PEX-INFO

    @property
    def is_pure(self) -> bool:
        return all(t.platform == "any" for t in self.tags)

    @property
    def platform_tags(self) -> list[str]:
        return sorted({t.platform for t in self.tags})

    @property
    def python_tags(self) -> list[str]:
        return sorted({t.interpreter for t in self.tags})

    @property
    def abi_tags(self) -> list[str]:
        return sorted({t.abi for t in self.tags})


@dataclass
class Pex:
    path: Path
    info: dict
    dists: list[Dist]
    total_bytes: int  # size of the PEX on disk
    bootstrap_bytes: int  # pex runtime vendored in .bootstrap/
    source_bytes: int  # everything that is not .deps/, .bootstrap/ or PEX-INFO
    layout: str  # "zipapp", "packed" or "loose"
    warnings: list[str] = field(default_factory=list)

    # Convenience accessors over PEX-INFO -------------------------------------------
    @property
    def requirements(self) -> list[str]:
        return list(self.info.get("requirements", []))

    @property
    def interpreter_constraints(self) -> list[str]:
        return list(self.info.get("interpreter_constraints", []))

    @property
    def entry_point(self) -> str | None:
        return self.info.get("entry_point") or self.info.get("script") or None

    @property
    def pex_version(self) -> str | None:
        return (self.info.get("build_properties") or {}).get("pex_version")

    @property
    def has_sources(self) -> bool:
        return self.info.get("code_hash") not in (None, EMPTY_SHA1)

    def by_project(self) -> dict[NormalizedName, list[Dist]]:
        out: dict[NormalizedName, list[Dist]] = {}
        for d in self.dists:
            out.setdefault(d.project, []).append(d)
        return out


# --------------------------------------------------------------------------------------
# Storage backends: a zip PEX and a directory PEX look the same to the parser.
# --------------------------------------------------------------------------------------


@dataclass
class _Entry:
    name: str  # path relative to the PEX root, POSIX style, no trailing slash
    stored: int
    size: int
    is_dir: bool


class _Store:
    def entries(self) -> list[_Entry]: ...

    def read(self, name: str) -> bytes: ...


class _ZipStore(_Store):
    def __init__(self, zf: zipfile.ZipFile):
        self.zf = zf

    def entries(self) -> list[_Entry]:
        return [
            _Entry(i.filename.rstrip("/"), i.compress_size, i.file_size, i.is_dir())
            for i in self.zf.infolist()
        ]

    def read(self, name: str) -> bytes:
        return self.zf.read(name)


class _DirStore(_Store):
    def __init__(self, root: Path):
        self.root = root

    def entries(self) -> list[_Entry]:
        out = []
        for p in sorted(self.root.rglob("*")):
            rel = p.relative_to(self.root).as_posix()
            if p.is_dir():
                out.append(_Entry(rel, 0, 0, True))
            else:
                n = p.stat().st_size
                out.append(_Entry(rel, n, n, False))
        return out

    def read(self, name: str) -> bytes:
        return (self.root / name).read_bytes()


# --------------------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------------------


def read_pex(path: str | Path) -> Pex:
    path = Path(path)
    if not path.exists():
        raise PexReadError(f"{path}: no such file or directory")

    if path.is_dir():
        store: _Store = _DirStore(path)
        layout = "loose"
        total = sum(e.size for e in store.entries())
        return _parse(path, store, layout, total)

    if not zipfile.is_zipfile(path):
        raise PexReadError(f"{path}: not a zip file, so not a PEX (scies are not supported yet)")
    with zipfile.ZipFile(path) as zf:
        return _parse(path, _ZipStore(zf), "zipapp", path.stat().st_size)


def _parse(path: Path, store: _Store, layout: str, total_bytes: int) -> Pex:
    try:
        info = json.loads(store.read("PEX-INFO"))
    except KeyError:
        raise PexReadError(f"{path}: no PEX-INFO found, so not a PEX") from None
    except FileNotFoundError:
        raise PexReadError(f"{path}: no PEX-INFO found, so not a PEX") from None

    entries = store.entries()
    hashes: dict[str, str] = info.get("distributions", {})

    # Group .deps/ entries by the top-level dist entry they belong to.
    groups: dict[str, list[_Entry]] = {}
    bootstrap = source = 0
    for e in entries:
        parts = PurePosixPath(e.name).parts
        if not parts:
            continue
        if parts[0] == DEPS_DIR:
            if len(parts) >= 2:
                groups.setdefault(parts[1], []).append(e)
        elif parts[0] == ".bootstrap":
            bootstrap += e.stored
        elif e.name != "PEX-INFO" and not e.is_dir:
            source += e.stored

    if layout == "loose" and any(
        not e.is_dir and len(PurePosixPath(e.name).parts) == 2 for g in groups.values() for e in g
    ):
        layout = "packed"

    warnings: list[str] = []
    dists = []
    for filename in sorted(groups):
        if not filename.endswith(".whl"):
            continue
        try:
            dists.append(_parse_dist(store, filename, groups[filename], hashes.get(filename)))
        except InvalidWheelFilename:
            warnings.append(f"Skipped {filename}: not a valid wheel file name")
    missing = sorted(set(hashes) - set(groups))
    for m in missing:
        warnings.append(f"PEX-INFO lists {m} but it is not in .deps/")

    return Pex(
        path=path,
        info=info,
        dists=dists,
        total_bytes=total_bytes,
        bootstrap_bytes=bootstrap,
        source_bytes=source,
        layout=layout,
        warnings=warnings,
    )


def _parse_dist(store: _Store, filename: str, group: list[_Entry], sha: str | None) -> Dist:
    project, version, _build, tags = parse_wheel_filename(filename)
    prefix = f"{DEPS_DIR}/{filename}"
    files = [e for e in group if not e.is_dir]

    single = [e for e in files if e.name == prefix]
    if single:
        # The dist is one zip file: an original wheel or a packed install chroot.
        blob = store.read(prefix)
        stored = single[0].stored
        with zipfile.ZipFile(io.BytesIO(blob)) as inner:
            infos = [i for i in inner.infolist() if not i.is_dir()]
            installed = sum(i.file_size for i in infos)
            count = len(infos)
            meta_name = _find_metadata([i.filename for i in infos])
            meta = inner.read(meta_name) if meta_name else None
    else:
        stored = sum(e.stored for e in files)
        installed = sum(e.size for e in files)
        count = len(files)
        rel = [e.name[len(prefix) + 1 :] for e in files]
        meta_name = _find_metadata(rel)
        meta = store.read(f"{prefix}/{meta_name}") if meta_name else None

    display, requires, lic = str(project), (), None
    if meta:
        msg = Parser().parsestr(meta.decode("utf-8", errors="replace"), headersonly=True)
        display = msg.get("Name", display)
        requires = tuple(_parse_reqs(msg.get_all("Requires-Dist") or []))
        lic = _license(msg)

    return Dist(
        filename=filename,
        project=canonicalize_name(project),
        display_name=display,
        version=str(version),
        tags=frozenset(tags),
        stored_bytes=stored,
        installed_bytes=installed,
        file_count=count,
        requires=requires,
        license=lic,
        sha256=sha,
    )


def _find_metadata(names: list[str]) -> str | None:
    for n in names:
        p = PurePosixPath(n)
        if len(p.parts) == 2 and p.parts[0].endswith(".dist-info") and p.name == "METADATA":
            return n
    return None


def _parse_reqs(lines: list[str]) -> list[Requirement]:
    out = []
    for line in lines:
        try:
            out.append(Requirement(line))
        except InvalidRequirement:
            continue
    return out


def _license(msg) -> str | None:
    # PEP 639 first, then the classic field, then trove classifiers.
    if expr := msg.get("License-Expression"):
        return expr.strip()
    lic = (msg.get("License") or "").strip()
    if lic and len(lic) <= 40 and "\n" not in lic and lic.upper() != "UNKNOWN":
        return lic
    for c in msg.get_all("Classifier") or []:
        if c.startswith("License :: OSI Approved :: "):
            return c.removeprefix("License :: OSI Approved :: ").removesuffix(" License")
    if lic and lic.upper() != "UNKNOWN":
        return lic.splitlines()[0][:40] + "…"
    return None
