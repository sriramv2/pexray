# pexray

**X-ray a [PEX](https://github.com/pex-tool/pex) file: what's inside, what it can actually run on, and what changed between builds — without executing it.**

> diffoscope tells you which *files* changed. pexray tells you which *dependencies* changed, by how much, and why they're there.

```
$ pexray info app.pex
╭─ app.pex ─────────────────────────────────────────────────────────╮
│ Requirements  PyQt6==6.11.0                                       │
│ Runs on       macos/x86_64  ·  Python 3.12 only                   │
│ Size          80.8 MB  (3 projects, 3 wheels)                     │
│ Breakdown     deps 78.5 MB · pex runtime 929.4 KB                 │
╰───────────────────────────────────────────────────────────────────╯
Project    Version  Platform                                     Size  Share
PyQt6-Qt6  6.11.2   macos/x86_64               ███████████▌   66.7 MB  82.6%
PyQt6      6.11.0   macos/arm64, macos/x86_64  ██             11.7 MB  14.5%
PyQt6_sip  13.13.0  macos/arm64, macos/x86_64                110.3 KB   0.1%

⚠ Won't run on macos/arm64: PyQt6-Qt6 has no arm64 build, though PyQt6, PyQt6_sip do.
```

```
$ pexray diff v1.4.pex v1.5.pex
╭───────────────────────────────────────────────────────────────────╮
│ v1.4.pex → v1.5.pex   3.2 MB → 3.6 MB   ▲ +400.1 KB (+12.3%)      │
╰───────────────────────────────────────────────────────────────────╯
Change      Project            Before  After      Δ size  Notes
+ added     anyio              —       4.15.1  +123.2 KB
+ added     httpx              —       0.27.2   +71.9 KB
▲ upgraded  requests           2.31.0  2.32.3    +2.3 KB
↻ rebuilt   numpy              2.1.2   2.1.2   −12.7 MB  drops macos/arm64

Why were these added?
  anyio:  httpx → anyio
  h11:    httpx → httpcore → h11
```

## Why

PEX files are great for shipping Python, but opaque once built. Existing tools each cover a slice:

| | Reads PEX layout | Per-dependency sizes | "Runs on" from wheel tags | Package-level diff | Why is X here? |
|---|:-:|:-:|:-:|:-:|:-:|
| `pex-tools info` | ✓ (raw PEX-INFO) | | | | |
| `pex-tools graph` | ✓ (needs a matching interpreter) | | | | via DOT |
| diffoscope | | | | file-level | |
| syft / SBOM tools | wheels | | | | |
| **pexray** | ✓ | ✓ | ✓ | ✓ | ✓ |

## What it checks

- **Platform gaps.** If one native wheel narrows where the PEX can run — say it's `x86_64`-only while its siblings are `universal2` — you get a warning naming the culprit. Classic cause: resolving under Rosetta or on the wrong machine.
- **Python version.** Works out which CPython versions the bundled wheels actually allow (`cp312` → 3.12 only, `abi3` → 3.x+), and notes when the PEX has no interpreter constraints to match.
- **Build-to-build regressions.** In `diff`: lost platforms, raised glibc floors (`manylinux2014` → `manylinux_2_28`), license changes, PEX setting changes.

## Install

```bash
pipx install pexray      # or: uv tool install pexray
```

(Not on PyPI yet — for now: `pipx install git+https://github.com/sriramv2/pexray`.)

## Usage

```bash
pexray info app.pex                    # summary, sizes, dependency tree, findings
pexray info app.pex --all              # every distribution
pexray info app.pex -f json            # machine-readable

pexray diff old.pex new.pex            # what changed, and why
pexray diff old.pex new.pex -f markdown >> $GITHUB_STEP_SUMMARY   # PR-ready

pexray why app.pex h11                 # httpx 0.27.2 → httpcore 1.0.9 → h11 0.16.0
```

`info` exits 1 if it finds an error (e.g. no platform satisfies every native dependency), so it can gate CI.

## How it works

pexray never runs the PEX and doesn't need pex installed. It reads the zip index, `PEX-INFO`, and each bundled distribution's `METADATA` directly — so a 1 GB PEX opens in well under a second, and a Linux PEX inspects fine on a Mac. All three storage modes are supported: zipapp (default), `--no-pre-install-wheels`, and `--layout packed|loose` directories.

Dependency edges are evaluated against the environments the wheels themselves target, so `rich → typing_extensions; python_version < "3.11"` correctly disappears from a 3.13-only PEX.

## Roadmap

- [ ] `--fail-on` for `diff` (size growth %, lost platforms) for CI gates
- [ ] CycloneDX / SPDX SBOM output
- [ ] Scie support
- [ ] Propose `diff` upstream as a `pex-tools` subcommand

## Development

```bash
pip install -e ".[dev]"
pytest                          # fast, offline: tests build tiny synthetic PEXes
tests/fixtures/build.sh         # optional: real PEXes from PyPI to try by hand
```
