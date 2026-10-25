from __future__ import annotations

import json
from enum import Enum
from pathlib import Path

import typer
from packaging.utils import canonicalize_name
from rich.console import Console

from . import __version__
from .analysis import analyze, why as why_paths
from .diff import diff_pex
from .reader import PexReadError, read_pex
from .render import diff_json, diff_markdown, info_json, render_diff, render_info

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="X-ray a PEX: what's inside, what it runs on, and what changed — without executing it.",
)
console = Console()
err = Console(stderr=True)


class Format(str, Enum):
    rich = "rich"
    json = "json"
    markdown = "markdown"


def _load(path: Path):
    try:
        return read_pex(path)
    except PexReadError as e:
        err.print(f"[red]error:[/] {e}")
        raise typer.Exit(2) from None


def _version(value: bool):
    if value:
        console.print(f"pexray {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
):
    pass


@app.command()
def info(
    pex: Path = typer.Argument(..., help="A .pex file or PEX directory."),
    fmt: Format = typer.Option(Format.rich, "--format", "-f", help="Output format."),
    show_all: bool = typer.Option(False, "--all", "-a", help="List every distribution."),
):
    """What's inside a PEX, what it can run on, and anything that looks wrong."""
    p = _load(pex)
    a = analyze(p)
    if fmt is Format.json:
        print(json.dumps(info_json(p, a), indent=2))
    elif fmt is Format.markdown:
        err.print("[yellow]markdown output is only implemented for diff; using rich[/]")
        render_info(console, p, a, show_all)
    else:
        render_info(console, p, a, show_all)
    if any(f.severity.value == "error" for f in a.findings):
        raise typer.Exit(1)


@app.command()
def diff(
    old: Path = typer.Argument(..., help="The baseline PEX."),
    new: Path = typer.Argument(..., help="The PEX to compare against it."),
    fmt: Format = typer.Option(Format.rich, "--format", "-f", help="Output format."),
    show_all: bool = typer.Option(False, "--all", "-a", help="Include unchanged distributions."),
):
    """Package-level diff: what was added, bumped, removed or rebuilt, and why."""
    d = diff_pex(_load(old), _load(new))
    if fmt is Format.json:
        print(json.dumps(diff_json(d), indent=2))
    elif fmt is Format.markdown:
        print(diff_markdown(d))
    else:
        render_diff(console, d, show_all)


@app.command()
def why(
    pex: Path = typer.Argument(..., help="A .pex file or PEX directory."),
    project: str = typer.Argument(..., help="The distribution to explain, e.g. numpy."),
):
    """Why is PROJECT in this PEX? Shows the requirement chains that pull it in."""
    p = _load(pex)
    a = analyze(p)
    name = canonicalize_name(project)
    projects = p.by_project()
    if name not in projects:
        err.print(f"[red]{project} is not in {pex.name}[/]")
        raise typer.Exit(1)
    paths = why_paths(a, name)
    if not paths:
        console.print(f"[yellow]{project}[/] is in the PEX but no requirement chain reaches it "
                      "(it may be gated by an environment marker, or added via --pex-repository).")
        return
    for path in paths:
        console.print(" → ".join(f"[bold]{projects[n][0].display_name}[/] {projects[n][0].version}" for n in path))
