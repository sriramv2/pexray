"""Package-level diff of two PEX files.

diffoscope tells you which files changed. This tells you which dependencies changed,
by how much, why they are there, and whether where the PEX can run changed too.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from packaging.utils import NormalizedName
from packaging.version import InvalidVersion, Version

from .analysis import Analysis, Platform, analyze, fmt_platforms, fmt_pythons, why
from .reader import Dist, Pex


class Change(str, Enum):
    added = "added"
    removed = "removed"
    upgraded = "upgraded"
    downgraded = "downgraded"
    rebuilt = "rebuilt"  # same version, different artifact (tags or hash changed)
    unchanged = "unchanged"


@dataclass
class DistChange:
    project: NormalizedName
    name: str
    change: Change
    old_version: str | None
    new_version: str | None
    old_bytes: int
    new_bytes: int
    old_platforms: list[str] = field(default_factory=list)
    new_platforms: list[str] = field(default_factory=list)
    old_license: str | None = None
    new_license: str | None = None
    why: list[list[str]] = field(default_factory=list)  # for added deps: who pulled it in

    @property
    def delta(self) -> int:
        return self.new_bytes - self.old_bytes

    @property
    def platforms_changed(self) -> bool:
        return self.old_platforms != self.new_platforms and self.change not in (
            Change.added,
            Change.removed,
        )

    @property
    def license_changed(self) -> bool:
        return self.change not in (Change.added, Change.removed) and _norm_license(
            self.old_license
        ) != _norm_license(self.new_license)


def _norm_license(s: str | None) -> str:
    """'Apache 2.0', 'Apache-2.0' and 'Apache Software License 2.0' compare equal."""
    import re

    s = (s or "").lower()
    s = re.sub(r"\b(software|license|licence|the|version)\b", "", s)
    return re.sub(r"[^a-z0-9.+]", "", s)


@dataclass
class PexDiff:
    old: Pex
    new: Pex
    old_analysis: Analysis
    new_analysis: Analysis
    changes: list[DistChange]
    info_changes: dict[str, tuple[object, object]]

    @property
    def delta(self) -> int:
        return self.new.total_bytes - self.old.total_bytes

    @property
    def changed(self) -> list[DistChange]:
        return [c for c in self.changes if c.change is not Change.unchanged]

    @property
    def platforms_lost(self) -> set[Platform]:
        o, n = self.old_analysis.platforms, self.new_analysis.platforms
        if o is None:
            return set() if n is None else {("any", "")}
        return o - (n if n is not None else o)

    @property
    def platforms_gained(self) -> set[Platform]:
        o, n = self.old_analysis.platforms, self.new_analysis.platforms
        if n is None or o is None:
            return set()
        return n - o

    @property
    def runs_on(self) -> tuple[str, str]:
        return (
            f"{fmt_platforms(self.old_analysis.platforms)} · Python {fmt_pythons(self.old_analysis.pythons)}",
            f"{fmt_platforms(self.new_analysis.platforms)} · Python {fmt_pythons(self.new_analysis.pythons)}",
        )


# PEX-INFO keys worth calling out when they change. Hashes always change; skip them.
_INFO_KEYS = (
    "entry_point",
    "script",
    "interpreter_constraints",
    "requirements",
    "inherit_path",
    "venv",
    "strip_pex_env",
    "includes_tools",
    "inject_args",
    "inject_env",
    "excluded",
    "overridden",
)


def _version_key(v: str):
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _summarize(dists: list[Dist]) -> tuple[str, int, list[str], str | None, set[str | None]]:
    versions = sorted({d.version for d in dists})
    return (
        ", ".join(versions),
        sum(d.stored_bytes for d in dists),
        sorted({p for d in dists for p in d.platform_tags}),
        dists[0].license,
        {d.sha256 for d in dists},
    )


def diff_pex(old: Pex, new: Pex) -> PexDiff:
    oa, na = analyze(old), analyze(new)
    op, np_ = old.by_project(), new.by_project()
    changes: list[DistChange] = []

    for name in sorted(set(op) | set(np_)):
        o, n = op.get(name), np_.get(name)
        if o and n:
            ov, ob, oplat, olic, ohash = _summarize(o)
            nv, nb, nplat, nlic, nhash = _summarize(n)
            if ov == nv:
                kind = Change.unchanged if (ohash == nhash and oplat == nplat) else Change.rebuilt
            else:
                ok, nk = _version_key(o[0].version), _version_key(n[0].version)
                kind = Change.downgraded if (ok and nk and nk < ok) else Change.upgraded
            changes.append(
                DistChange(name, n[0].display_name, kind, ov, nv, ob, nb, oplat, nplat, olic, nlic)
            )
        elif n:
            nv, nb, nplat, nlic, _ = _summarize(n)
            paths = [[new.by_project()[p][0].display_name for p in path] for path in why(na, name)]
            changes.append(
                DistChange(name, n[0].display_name, Change.added, None, nv, 0, nb, [], nplat, None, nlic, paths)
            )
        else:
            assert o
            ov, ob, oplat, olic, _ = _summarize(o)
            changes.append(
                DistChange(name, o[0].display_name, Change.removed, ov, None, ob, 0, oplat, [], olic, None)
            )

    order = {Change.added: 0, Change.upgraded: 1, Change.downgraded: 1, Change.rebuilt: 2,
             Change.removed: 3, Change.unchanged: 4}
    changes.sort(key=lambda c: (order[c.change], -abs(c.delta), c.project))

    info_changes = {}
    for k in _INFO_KEYS:
        a, b = old.info.get(k), new.info.get(k)
        if a != b:
            info_changes[k] = (a, b)

    return PexDiff(old, new, oa, na, changes, info_changes)
