"""Work out what a PEX can actually run on, and flag anything surprising.

The question no existing tool answers quickly: given the wheels bundled in this PEX,
which OS/CPU/Python combinations can it run on? Every project with native code
narrows the set. If one project narrows it more than the rest — say, one wheel is
x86_64-only while its siblings are universal2 — that is almost always a mistake.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from packaging.markers import default_environment
from packaging.utils import NormalizedName, canonicalize_name

from .reader import Dist, Pex

# Python minor versions we reason about. Wide enough for anything a PEX targets today.
PY_MINORS = tuple(range(7, 16))

Platform = tuple[str, str]  # (os, arch)


class Severity(str, Enum):
    error = "error"
    warning = "warning"
    info = "info"


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str
    detail: str | None = None


@dataclass
class Analysis:
    platforms: set[Platform] | None  # None: no native code, runs anywhere Python does
    pythons: set[int] | None  # minor versions (3.x); None: no constraint from wheels
    narrowed_by: dict[str, list[str]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    graph: dict[NormalizedName, list[NormalizedName]] = field(default_factory=dict)
    roots: list[NormalizedName] = field(default_factory=list)


# --------------------------------------------------------------------------------------
# Platform tags -> (os, arch)
# --------------------------------------------------------------------------------------

_MAC_FAT = {
    "universal2": {"x86_64", "arm64"},
    "universal": {"x86_64", "i386", "ppc", "ppc64"},
    "intel": {"x86_64", "i386"},
    "fat": {"i386", "ppc"},
    "fat3": {"x86_64", "i386", "ppc"},
    "fat64": {"x86_64", "ppc64"},
}
_ARCH_ALIASES = {"aarch64": "arm64", "amd64": "x86_64", "i686": "x86", "i386": "x86", "win32": "x86"}


def _arch(a: str) -> str:
    return _ARCH_ALIASES.get(a, a)


def platforms_of_tag(platform_tag: str) -> set[Platform] | None:
    """Return the (os, arch) pairs a wheel platform tag runs on; None for 'any'."""
    t = platform_tag
    if t == "any":
        return None
    if t.startswith("macosx_"):
        arch = re.sub(r"^macosx_\d+_\d+_", "", t)
        return {("macos", _arch(a)) for a in _MAC_FAT.get(arch, {arch})}
    if m := re.match(r"^(?:many|musl)linux(?:1|2010|2014|_\d+_\d+)_(.+)$", t) or re.match(
        r"^linux_(.+)$", t
    ):
        return {("linux", _arch(m.group(1)))}
    if t == "win32":
        return {("windows", "x86")}
    if t.startswith("win_"):
        return {("windows", _arch(t[4:]))}
    # ios_*, android_*, emscripten_*… : keep the raw tag so it still compares.
    return {(t, "")}


_LEGACY_MANYLINUX = {"manylinux1": (2, 5), "manylinux2010": (2, 12), "manylinux2014": (2, 17)}


def glibc_floor(platform_tags: list[str]) -> tuple[int, int] | None:
    """Lowest glibc a set of manylinux tags installs on (a wheel installs if any tag fits)."""
    floors = []
    for t in platform_tags:
        if m := re.match(r"^manylinux_(\d+)_(\d+)_", t):
            floors.append((int(m.group(1)), int(m.group(2))))
        elif m := re.match(r"^(manylinux1|manylinux2010|manylinux2014)_", t):
            floors.append(_LEGACY_MANYLINUX[m.group(1)])
    return min(floors) if floors else None


def dist_platforms(d: Dist) -> set[Platform] | None:
    out: set[Platform] = set()
    for t in d.tags:
        p = platforms_of_tag(t.platform)
        if p is None:
            return None
        out |= p
    return out


def dist_pythons(d: Dist) -> set[int] | None:
    """Python 3 minor versions this wheel can be installed for; None if unconstrained."""
    out: set[int] = set()
    for t in d.tags:
        m = re.fullmatch(r"(cp|py|pp)(\d)(\d*)", t.interpreter)
        if not m or m.group(2) != "3":
            continue  # py2, graalpy, etc.: not a CPython 3 constraint
        if not m.group(3):
            return None  # py3: any Python 3
        minor = int(m.group(3))
        if m.group(1) == "cp" and t.abi not in ("abi3", "none"):
            out.add(minor)  # version-specific ABI: exactly this minor
        else:
            out |= {v for v in PY_MINORS if v >= minor}  # abi3 / py3X: this or newer
    return out or None


def _fmt_platform(p: Platform) -> str:
    os_, arch = p
    return f"{os_}/{arch}" if arch else os_


def fmt_platforms(ps: set[Platform] | None) -> str:
    if ps is None:
        return "any"
    if not ps:
        return "nothing"
    return ", ".join(sorted(_fmt_platform(p) for p in ps))


def fmt_pythons(vs: set[int] | None) -> str:
    if vs is None:
        return "any Python 3"
    if not vs:
        return "nothing"
    s = sorted(vs)
    if s == list(range(s[0], PY_MINORS[-1] + 1)) and len(s) > 1:
        return f"3.{s[0]}+"
    if len(s) == 1:
        return f"3.{s[0]} only"
    return ", ".join(f"3.{v}" for v in s)


# --------------------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------------------


def analyze(pex: Pex) -> Analysis:
    projects = pex.by_project()

    # 1. Platform coverage: per project, the union over its wheels; overall, the intersection.
    per_project_plat: dict[NormalizedName, set[Platform]] = {}
    per_project_py: dict[NormalizedName, set[int]] = {}
    for name, dists in projects.items():
        plats: set[Platform] | None = set()
        for d in dists:
            p = dist_platforms(d)
            plats = None if (p is None or plats is None) else plats | p
        if plats is not None:
            per_project_plat[name] = plats
        pys: set[int] | None = set()
        for d in dists:
            v = dist_pythons(d)
            pys = None if (v is None or pys is None) else pys | v
        if pys is not None:
            per_project_py[name] = pys

    platforms: set[Platform] | None = None
    for plats in per_project_plat.values():
        platforms = set(plats) if platforms is None else platforms & plats
    pythons: set[int] | None = None
    for pys in per_project_py.values():
        pythons = set(pys) if pythons is None else pythons & pys

    a = Analysis(platforms=platforms, pythons=pythons)
    names = {n: projects[n][0].display_name for n in projects}

    # 2. Who narrowed it? A platform some native project supports but another lacks.
    if per_project_plat:
        offered = set().union(*per_project_plat.values())
        for plat in sorted(offered - (platforms or set())):
            lacking = sorted(names[n] for n, ps in per_project_plat.items() if plat not in ps)
            having = sorted(names[n] for n, ps in per_project_plat.items() if plat in ps)
            a.narrowed_by[_fmt_platform(plat)] = lacking
            # Only shout when the gap looks accidental: same OS is otherwise supported.
            same_os_ok = platforms and any(p[0] == plat[0] for p in platforms)
            if same_os_ok:
                a.findings.append(
                    Finding(
                        Severity.warning,
                        "platform-gap",
                        f"Won't run on {_fmt_platform(plat)}: {', '.join(lacking)} "
                        f"has no {plat[1]} build, though {', '.join(having)} "
                        f"{'does' if len(having) == 1 else 'do'}.",
                        "Usually a resolve on the wrong machine or an x86_64 interpreter "
                        "under Rosetta. Rebuild with --platform/--complete-platform for "
                        "every target.",
                    )
                )

    if platforms is not None and not platforms:
        a.findings.append(
            Finding(
                Severity.error,
                "no-platform",
                "No single platform satisfies every native dependency — this PEX "
                "cannot run anywhere as built.",
                "; ".join(f"{names[n]}: {fmt_platforms(p)}" for n, p in per_project_plat.items()),
            )
        )
    if pythons is not None and not pythons:
        a.findings.append(
            Finding(
                Severity.error,
                "no-python",
                "No single Python version satisfies every native dependency.",
                "; ".join(f"{names[n]}: {fmt_pythons(p)}" for n, p in per_project_py.items()),
            )
        )

    # 3. Lints from PEX-INFO.
    if not pex.interpreter_constraints and pythons:
        a.findings.append(
            Finding(
                Severity.info,
                "no-interpreter-constraints",
                f"No interpreter constraints, but the bundled wheels need Python "
                f"{fmt_pythons(pythons)}.",
                f"Add --interpreter-constraint so the PEX picks the right Python "
                f"instead of failing at import time.",
            )
        )
    if not pex.has_sources:
        a.findings.append(
            Finding(Severity.info, "deps-only", "Contains no application sources (dependencies only).")
        )
    for w in pex.warnings:
        a.findings.append(Finding(Severity.warning, "layout", w))

    # 4. Dependency graph, restricted to what is in the PEX and evaluated against the
    #    environments the wheels say it targets.
    a.graph, a.roots = build_graph(pex, target_envs(platforms, pythons))
    return a


_SYS_PLATFORM = {"linux": ("linux", "Linux"), "macos": ("darwin", "Darwin"), "windows": ("win32", "Windows")}
_MACHINE = {
    ("linux", "arm64"): "aarch64",
    ("windows", "x86_64"): "AMD64",
    ("windows", "x86"): "x86",
    ("windows", "arm64"): "ARM64",
}


def target_envs(platforms: set[Platform] | None, pythons: set[int] | None) -> list[dict]:
    """Marker environments for every (platform, python) the PEX can run on.

    Fields we can't know (or that don't matter) keep values from this machine. When the
    wheels don't constrain something, we leave it as None and evaluation falls back to
    "keep the edge": better to show a dependency that might not apply than hide one.
    """
    base = default_environment()
    envs = []
    plats = sorted(platforms) if platforms else [None]
    pys = sorted(pythons) if pythons else [None]
    for plat in plats:
        for py in pys:
            env = dict(base)
            if plat and plat[0] in _SYS_PLATFORM:
                env["sys_platform"], env["platform_system"] = _SYS_PLATFORM[plat[0]]
                env["os_name"] = "nt" if plat[0] == "windows" else "posix"
                env["platform_machine"] = _MACHINE.get(plat, plat[1])
            if py:
                env["python_version"] = f"3.{py}"
                env["python_full_version"] = f"3.{py}.0"
            env["_unconstrained"] = plat is None or py is None
            envs.append(env)
    return envs


def build_graph(
    pex: Pex, envs: list[dict] | None = None
) -> tuple[dict[NormalizedName, list[NormalizedName]], list[NormalizedName]]:
    from packaging.requirements import InvalidRequirement, Requirement

    projects = pex.by_project()
    envs = envs or target_envs(None, None)

    # Which extras does anything ask for? Over-approximate: any requirement anywhere.
    extras: dict[NormalizedName, set[str]] = {}
    all_reqs = [r for ds in projects.values() for r in ds[0].requires]
    for line in pex.requirements:
        try:
            all_reqs.append(Requirement(line))
        except InvalidRequirement:
            pass
    for r in all_reqs:
        if r.extras:
            extras.setdefault(canonicalize_name(r.name), set()).update(r.extras)

    graph: dict[NormalizedName, list[NormalizedName]] = {}
    for name, dists in projects.items():
        edges: set[NormalizedName] = set()
        for req in dists[0].requires:
            dep = canonicalize_name(req.name)
            if dep not in projects or dep == name:
                continue
            if req.marker is not None and not _applies(req.marker, envs, extras.get(name, set())):
                continue
            edges.add(dep)
        graph[name] = sorted(edges)

    roots: list[NormalizedName] = []
    for r in pex.requirements:
        try:
            from packaging.requirements import Requirement

            n = canonicalize_name(Requirement(r).name)
        except Exception:
            continue
        if n in projects and n not in roots:
            roots.append(n)
    if not roots:  # e.g. built from a lock or requirements file: use the undepended-upon
        depended = {d for deps in graph.values() for d in deps}
        roots = sorted(n for n in graph if n not in depended)
    return graph, roots


def _applies(marker, envs: list[dict], extras: set[str]) -> bool:
    """Does this marker hold in at least one environment the PEX targets?"""
    text = str(marker)
    for env in envs:
        unconstrained = env.get("_unconstrained", False)
        if unconstrained and "extra" not in text:
            return True  # we can't tell; show the edge rather than hide it
        clean = {k: v for k, v in env.items() if not k.startswith("_")}
        for extra in ("", *sorted(extras)):
            try:
                if marker.evaluate({**clean, "extra": extra}):
                    return True
            except Exception:
                return True
    return False


def why(analysis: Analysis, target: NormalizedName) -> list[list[NormalizedName]]:
    """All shortest paths from a root requirement to target."""
    from collections import deque

    paths: list[list[NormalizedName]] = []
    best: int | None = None
    q = deque([[r] for r in analysis.roots])
    seen_depth: dict[NormalizedName, int] = {}
    while q:
        path = q.popleft()
        node = path[-1]
        if best is not None and len(path) > best:
            break
        if node == target:
            best = len(path)
            paths.append(path)
            continue
        if seen_depth.get(node, 1 << 30) < len(path):
            continue
        seen_depth[node] = len(path)
        for nxt in analysis.graph.get(node, []):
            if nxt not in path:
                q.append(path + [nxt])
    return paths
