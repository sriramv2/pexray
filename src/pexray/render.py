"""Output: Rich for humans, JSON for machines, Markdown for PR comments."""

from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from .analysis import Analysis, Finding, Severity, fmt_platforms, fmt_pythons, glibc_floor, platforms_of_tag
from .diff import Change, DistChange, PexDiff
from .reader import Pex

SEV_STYLE = {Severity.error: "bold red", Severity.warning: "yellow", Severity.info: "cyan"}
SEV_ICON = {Severity.error: "✖", Severity.warning: "⚠", Severity.info: "ℹ"}


def human_bytes(n: int, signed: bool = False) -> str:
    sign = ("+" if n > 0 else "−" if n < 0 else "±") if signed else ("-" if n < 0 else "")
    v = float(abs(n))
    for unit in ("B", "KB", "MB", "GB"):
        if v < 1024 or unit == "GB":
            s = f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
            return f"{sign}{s}"
        v /= 1024
    raise AssertionError


def _bar(frac: float, width: int = 14) -> str:
    full = int(frac * width)
    return "█" * full + ("▌" if frac * width - full >= 0.5 else "")


def _findings(findings: list[Finding]) -> Group | None:
    if not findings:
        return None
    lines = []
    for f in findings:
        t = Text()
        t.append(f"{SEV_ICON[f.severity]} ", style=SEV_STYLE[f.severity])
        t.append(f.message, style=SEV_STYLE[f.severity] if f.severity is not Severity.info else "")
        lines.append(t)
        if f.detail:
            lines.append(Text(f"  {f.detail}", style="dim"))
    return Group(*lines)


# --------------------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------------------


def render_info(console: Console, pex: Pex, a: Analysis, show_all: bool = False) -> None:
    deps_bytes = sum(d.stored_bytes for d in pex.dists)
    projects = pex.by_project()

    head = Table.grid(padding=(0, 2))
    head.add_column(style="bold")
    head.add_column()
    if pex.entry_point:
        head.add_row("Entry point", pex.entry_point)
    head.add_row("Requirements", ", ".join(pex.requirements) or "—")
    head.add_row(
        "Runs on",
        Text(f"{fmt_platforms(a.platforms)}  ·  Python {fmt_pythons(a.pythons)}", style="bold green"
             if a.platforms is None or a.platforms else "bold red"),
    )
    if pex.interpreter_constraints:
        head.add_row("Interpreter", ", ".join(pex.interpreter_constraints))
    head.add_row(
        "Size",
        f"{human_bytes(pex.total_bytes)}  ({len(projects)} projects, {len(pex.dists)} wheels"
        f"{', ' + pex.layout + ' layout' if pex.layout != 'zipapp' else ''})",
    )
    head.add_row(
        "Breakdown",
        f"deps {human_bytes(deps_bytes)} · pex runtime {human_bytes(pex.bootstrap_bytes)}"
        f"{' · app ' + human_bytes(pex.source_bytes) if pex.has_sources else ''}",
    )
    if pex.pex_version:
        head.add_row("Built with", f"pex {pex.pex_version}")
    console.print(Panel(head, title=f"[bold]{pex.path.name}[/]", title_align="left", border_style="blue"))

    # Dists by size
    t = Table(box=None, pad_edge=False, header_style="bold")
    t.add_column("Project")
    t.add_column("Version")
    t.add_column("Platform", overflow="fold")
    t.add_column("", no_wrap=True)
    t.add_column("Size", justify="right")
    t.add_column("Share", justify="right")
    t.add_column("License", overflow="fold")
    rows = sorted(pex.dists, key=lambda d: -d.stored_bytes)
    limit = len(rows) if show_all else 12
    for d in rows[:limit]:
        frac = d.stored_bytes / pex.total_bytes if pex.total_bytes else 0
        plat = "any" if d.is_pure else fmt_platforms(_coverage(d.platform_tags))
        if floor := glibc_floor(d.platform_tags):
            plat += f" · glibc≥{floor[0]}.{floor[1]}"
        flagged = any(d.display_name in x.message for x in a.findings if x.code == "platform-gap")
        t.add_row(
            d.display_name,
            d.version,
            Text(plat, style="yellow" if flagged else "dim" if d.is_pure else ""),
            Text(_bar(frac), style="magenta"),
            human_bytes(d.stored_bytes),
            f"{frac:.1%}",
            Text(d.license or "unknown", style="" if d.license else "yellow"),
        )
    if len(rows) > limit:
        rest = rows[limit:]
        t.add_row(f"… {len(rest)} more", "", "", "", human_bytes(sum(d.stored_bytes for d in rest)),
                  f"{sum(d.stored_bytes for d in rest) / pex.total_bytes:.1%}", "", style="dim")
    console.print(t)

    # Dependency tree
    if a.roots:
        console.print()
        tree = Tree(Text(pex.path.name, style="bold"), guide_style="dim")
        seen: set[str] = set()

        def add(node, name, depth=0):
            d = projects[name][0]
            label = Text(f"{d.display_name} ", style="bold" if depth == 0 else "")
            label.append(d.version, style="dim")
            if name in seen and a.graph.get(name):
                label.append(" (see above)", style="dim italic")
                node.add(label)
                return
            seen.add(name)
            child = node.add(label)
            for dep in a.graph.get(name, []):
                add(child, dep, depth + 1)

        for r in a.roots:
            add(tree, r)
        console.print(tree)

    # Findings
    if group := _findings(a.findings):
        console.print()
        console.print(group)


# --------------------------------------------------------------------------------------
# diff
# --------------------------------------------------------------------------------------

_CHANGE_STYLE = {
    Change.added: ("+ added", "green"),
    Change.removed: ("− removed", "red"),
    Change.upgraded: ("▲ upgraded", "cyan"),
    Change.downgraded: ("▼ downgraded", "magenta"),
    Change.rebuilt: ("↻ rebuilt", "yellow"),
    Change.unchanged: ("  same", "dim"),
}


def render_diff(console: Console, d: PexDiff, show_all: bool = False) -> None:
    pct = d.delta / d.old.total_bytes if d.old.total_bytes else 0
    grew = d.delta > 0
    head = Text()
    head.append(f"{d.old.path.name} → {d.new.path.name}   ", style="bold")
    head.append(f"{human_bytes(d.old.total_bytes)} → {human_bytes(d.new.total_bytes)}   ")
    head.append(
        f"{'▲' if grew else '▼' if d.delta < 0 else '='} {human_bytes(d.delta, signed=True)} ({pct:+.1%})",
        style="bold red" if grew else "bold green",
    )
    console.print(Panel(head, border_style="blue"))

    rows = d.changes if show_all else d.changed
    if not rows:
        console.print("[green]No dependency changes.[/]")
    else:
        t = Table(box=None, pad_edge=False, header_style="bold")
        t.add_column("Change", no_wrap=True)
        t.add_column("Project")
        t.add_column("Before")
        t.add_column("After")
        t.add_column("Δ size", justify="right")
        t.add_column("Notes", overflow="fold")
        for c in rows:
            label, style = _CHANGE_STYLE[c.change]
            notes = _notes(c)
            t.add_row(
                Text(label, style=style),
                c.name,
                c.old_version or "—",
                c.new_version or "—",
                Text(human_bytes(c.delta, signed=True), style="red" if c.delta > 0 else "green" if c.delta < 0 else "dim"),
                Text(notes, style="yellow" if notes else ""),
            )
        console.print(t)

    # Why are new things here?
    added = [c for c in d.changed if c.change is Change.added and c.why]
    if added:
        console.print()
        console.print("[bold]Why were these added?[/]")
        for c in added:
            for path in c.why[:2]:
                line = Text("  ")
                line.append(c.name, style="green")
                line.append(":  " + (" → ".join(path) if len(path) > 1 else "direct requirement"))
                console.print(line)

    # Where it runs
    before, after = d.runs_on
    if before != after:
        console.print()
        console.print("[bold]Runs on[/]")
        console.print(f"  before: {before}")
        style = "bold red" if d.platforms_lost else "bold green"
        console.print(Text(f"  after:  {after}", style=style))

    if d.info_changes:
        console.print()
        console.print("[bold]PEX settings changed[/]")
        for k, (a, b) in d.info_changes.items():
            console.print(f"  {k}: [red]{a!r}[/] → [green]{b!r}[/]")

    new_findings = _new_findings(d)
    if group := _findings(new_findings):
        console.print()
        console.print("[bold]New findings in the new build[/]")
        console.print(group)


def _coverage(tags: list[str]):
    out = set()
    for t in tags:
        p = platforms_of_tag(t)
        if p is None:
            return None
        out |= p
    return out


def _notes(c: DistChange) -> str:
    notes = []
    if c.platforms_changed:
        old, new = _coverage(c.old_platforms), _coverage(c.new_platforms)
        if old != new and old is not None and new is not None:
            if lost := old - new:
                notes.append(f"drops {fmt_platforms(lost)}")
            if gained := new - old:
                notes.append(f"adds {fmt_platforms(gained)}")
        elif old != new:
            notes.append(f"now {'pure Python' if new is None else fmt_platforms(new)}")
        og, ng = glibc_floor(c.old_platforms), glibc_floor(c.new_platforms)
        if og and ng and ng > og:
            notes.append(f"needs glibc ≥ {ng[0]}.{ng[1]} (was {og[0]}.{og[1]})")
        if not notes:
            notes.append(f"tags: {', '.join(c.old_platforms)} → {', '.join(c.new_platforms)}")
    if c.license_changed:
        notes.append(f"license: {c.old_license or '?'} → {c.new_license or '?'}")
    return "; ".join(notes)


def _new_findings(d: PexDiff) -> list[Finding]:
    old = {(f.code, f.message) for f in d.old_analysis.findings}
    return [f for f in d.new_analysis.findings if (f.code, f.message) not in old and f.severity is not Severity.info]


def diff_markdown(d: PexDiff) -> str:
    pct = d.delta / d.old.total_bytes if d.old.total_bytes else 0
    icon = "📈" if d.delta > 0 else "📉" if d.delta < 0 else "📦"
    out = [
        f"### {icon} `{d.new.path.name}` {'grew' if d.delta > 0 else 'shrank' if d.delta < 0 else 'is unchanged in size'}"
        f" {human_bytes(d.delta, signed=True)} ({pct:+.1%})",
        "",
        f"{human_bytes(d.old.total_bytes)} → {human_bytes(d.new.total_bytes)} · "
        f"{len(d.changed)} dependency change{'s' if len(d.changed) != 1 else ''}",
        "",
    ]
    if d.platforms_lost:
        out += [f"> [!WARNING]\n> No longer runs on: {fmt_platforms(d.platforms_lost)}", ""]
    for f in _new_findings(d):
        out += [f"> [!{'CAUTION' if f.severity is Severity.error else 'WARNING'}]\n> {f.message}", ""]
    if d.changed:
        out += ["<details><summary>Dependency changes</summary>", "",
                "| Change | Project | Before | After | Δ size | Notes |",
                "|---|---|---|---|--:|---|"]
        for c in d.changed:
            label = _CHANGE_STYLE[c.change][0].strip()
            out.append(
                f"| {label} | `{c.name}` | {c.old_version or '—'} | {c.new_version or '—'} "
                f"| {human_bytes(c.delta, signed=True)} | {_notes(c)} |"
            )
        out.append("")
        added = [c for c in d.changed if c.change is Change.added and c.why]
        if added:
            out.append("**Why were these added?**")
            out.append("")
            for c in added:
                path = c.why[0]
                out.append(f"- `{c.name}`: {' → '.join(path) if len(path) > 1 else 'direct requirement'}")
            out.append("")
        out.append("</details>")
    before, after = d.runs_on
    if before != after:
        out += ["", f"**Runs on:** {before} → **{after}**"]
    out += ["", "<sub>Generated by pexray</sub>"]
    return "\n".join(out)


# --------------------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------------------


def info_json(pex: Pex, a: Analysis) -> dict:
    return {
        "path": str(pex.path),
        "layout": pex.layout,
        "pex_version": pex.pex_version,
        "entry_point": pex.entry_point,
        "requirements": pex.requirements,
        "interpreter_constraints": pex.interpreter_constraints,
        "size": {
            "total": pex.total_bytes,
            "deps": sum(d.stored_bytes for d in pex.dists),
            "pex_runtime": pex.bootstrap_bytes,
            "other": pex.source_bytes,
        },
        "runs_on": {
            "platforms": None if a.platforms is None else sorted(f"{o}/{c}".rstrip("/") for o, c in a.platforms),
            "python": None if a.pythons is None else sorted(f"3.{v}" for v in a.pythons),
        },
        "distributions": [
            {
                "project": d.project,
                "name": d.display_name,
                "version": d.version,
                "filename": d.filename,
                "platform_tags": d.platform_tags,
                "python_tags": d.python_tags,
                "abi_tags": d.abi_tags,
                "stored_bytes": d.stored_bytes,
                "installed_bytes": d.installed_bytes,
                "files": d.file_count,
                "license": d.license,
                "sha256": d.sha256,
                "requires": sorted(a.graph.get(d.project, [])),
            }
            for d in sorted(pex.dists, key=lambda d: (d.project, d.filename))
        ],
        "roots": a.roots,
        "findings": [
            {"severity": f.severity.value, "code": f.code, "message": f.message, "detail": f.detail}
            for f in a.findings
        ],
    }


def diff_json(d: PexDiff) -> dict:
    return {
        "old": str(d.old.path),
        "new": str(d.new.path),
        "size": {"old": d.old.total_bytes, "new": d.new.total_bytes, "delta": d.delta},
        "runs_on": {"old": d.runs_on[0], "new": d.runs_on[1]},
        "platforms_lost": sorted(f"{o}/{c}".rstrip("/") for o, c in d.platforms_lost),
        "changes": [
            {
                "project": c.project,
                "name": c.name,
                "change": c.change.value,
                "old_version": c.old_version,
                "new_version": c.new_version,
                "delta_bytes": c.delta,
                "old_platform_tags": c.old_platforms,
                "new_platform_tags": c.new_platforms,
                "old_license": c.old_license,
                "new_license": c.new_license,
                "why": c.why,
            }
            for c in d.changed
        ],
        "info_changes": {k: {"old": a, "new": b} for k, (a, b) in d.info_changes.items()},
        "new_findings": [
            {"severity": f.severity.value, "code": f.code, "message": f.message} for f in _new_findings(d)
        ],
    }
