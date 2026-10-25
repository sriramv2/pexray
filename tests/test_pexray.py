from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from pexray.analysis import analyze, dist_pythons, fmt_pythons, glibc_floor, platforms_of_tag, why
from pexray.cli import app
from pexray.diff import Change, diff_pex
from pexray.reader import PexReadError, read_pex

QT = [
    ("pyqt6-6.11.0-cp310-abi3-macosx_10_14_universal2.whl",
     ["PyQt6-sip<14,>=13.8", "PyQt6-Qt6<6.12.0,>=6.11.0"], "GPL-3.0-only", 1000),
    ("pyqt6_qt6-6.11.2-py3-none-macosx_10_14_x86_64.whl", [], "LGPL-3.0-only", 5000),
    ("pyqt6_sip-13.13.0-cp312-cp312-macosx_10_9_universal2.whl", [], "BSD-2-Clause", 100),
]

HTTP_OLD = [
    ("requests-2.31.0-py3-none-any.whl", ["idna<4,>=2.5", "urllib3<3"], "Apache 2.0", 600),
    ("idna-3.7-py3-none-any.whl", [], "BSD-3-Clause", 300),
    ("urllib3-2.2.0-py3-none-any.whl", ['h2<5,>=4; extra == "h2"'], "MIT", 400),
]
HTTP_NEW = [
    ("requests-2.32.3-py3-none-any.whl", ["idna<4,>=2.5", "urllib3<3"], "Apache-2.0", 650),
    ("idna-3.7-py3-none-any.whl", [], "BSD-3-Clause", 300),
    ("urllib3-2.2.0-py3-none-any.whl", ['h2<5,>=4; extra == "h2"'], "MIT", 400),
    ("httpx-0.27.2-py3-none-any.whl", ["httpcore==1.*", "idna"], "BSD-3-Clause", 700),
    ("httpcore-1.0.9-py3-none-any.whl", ["h11>=0.16"], "BSD-3-Clause", 500),
    ("h11-0.16.0-py3-none-any.whl", [], "MIT", 200),
]


# ---------------------------------------------------------------------------- reader


@pytest.mark.parametrize("mode", ["unpacked", "wheel_files", "directory"])
def test_reads_every_storage_mode(make_pex, mode):
    p = read_pex(
        make_pex("qt.pex", QT, ["PyQt6"], wheel_files=mode == "wheel_files", directory=mode == "directory")
    )
    assert sorted(d.project for d in p.dists) == ["pyqt6", "pyqt6-qt6", "pyqt6-sip"]
    qt6 = next(d for d in p.dists if d.project == "pyqt6-qt6")
    assert qt6.version == "6.11.2"
    assert qt6.installed_bytes >= 5000
    assert qt6.license == "LGPL-3.0-only"
    assert qt6.sha256 == f"sha-{qt6.filename}"
    assert not p.has_sources


def test_not_a_pex(tmp_path):
    f = tmp_path / "nope.pex"
    f.write_text("hello")
    with pytest.raises(PexReadError):
        read_pex(f)


# ---------------------------------------------------------------------------- tags


@pytest.mark.parametrize(
    "tag, expected",
    [
        ("any", None),
        ("macosx_10_14_universal2", {("macos", "x86_64"), ("macos", "arm64")}),
        ("macosx_11_0_arm64", {("macos", "arm64")}),
        ("manylinux_2_17_x86_64", {("linux", "x86_64")}),
        ("manylinux2014_aarch64", {("linux", "arm64")}),
        ("musllinux_1_2_x86_64", {("linux", "x86_64")}),
        ("win_amd64", {("windows", "x86_64")}),
    ],
)
def test_platforms_of_tag(tag, expected):
    assert platforms_of_tag(tag) == expected


def test_glibc_floor():
    assert glibc_floor(["manylinux2014_x86_64", "manylinux_2_17_x86_64"]) == (2, 17)
    assert glibc_floor(["manylinux_2_28_x86_64"]) == (2, 28)
    assert glibc_floor(["macosx_11_0_arm64"]) is None


def test_python_tags(make_pex):
    p = read_pex(make_pex("qt.pex", QT))
    by = {d.project: d for d in p.dists}
    assert fmt_pythons(dist_pythons(by["pyqt6"])) == "3.10+"  # abi3
    assert fmt_pythons(dist_pythons(by["pyqt6-sip"])) == "3.12 only"
    assert dist_pythons(by["pyqt6-qt6"]) is None  # py3-none


# ---------------------------------------------------------------------------- analysis


def test_flags_the_one_wheel_that_narrows_the_platforms(make_pex):
    a = analyze(read_pex(make_pex("qt.pex", QT, ["PyQt6"])))
    assert a.platforms == {("macos", "x86_64")}
    assert a.pythons == {12}
    gap = [f for f in a.findings if f.code == "platform-gap"]
    assert len(gap) == 1
    assert "macos/arm64" in gap[0].message and "pyqt6_qt6" in gap[0].message.lower()
    assert any(f.code == "no-interpreter-constraints" for f in a.findings)


def test_no_constraint_lint_when_constraints_set(make_pex):
    a = analyze(read_pex(make_pex("qt.pex", QT, ["PyQt6"], interpreter_constraints=["==3.12.*"])))
    assert not any(f.code == "no-interpreter-constraints" for f in a.findings)


def test_pure_python_runs_anywhere(make_pex):
    a = analyze(read_pex(make_pex("http.pex", HTTP_OLD, ["requests"])))
    assert a.platforms is None and a.pythons is None
    assert not [f for f in a.findings if f.severity.value != "info"]


def test_graph_and_why(make_pex):
    a = analyze(read_pex(make_pex("http.pex", HTTP_NEW, ["requests", "httpx"])))
    assert a.roots == ["requests", "httpx"]
    assert why(a, "h11") == [["httpx", "httpcore", "h11"]]
    assert sorted(map(tuple, why(a, "idna"))) == [("httpx", "idna"), ("requests", "idna")]


def test_extra_gated_edges_are_dropped_unless_requested(make_pex):
    dists = HTTP_OLD + [("h2-4.1.0-py3-none-any.whl", [], "MIT", 10)]
    a = analyze(read_pex(make_pex("a.pex", dists, ["requests"])))
    assert "h2" not in a.graph["urllib3"]
    a = analyze(read_pex(make_pex("b.pex", dists, ["requests", "urllib3[h2]"])))
    assert "h2" in a.graph["urllib3"]


# ---------------------------------------------------------------------------- diff


def test_diff(make_pex):
    d = diff_pex(
        read_pex(make_pex("old.pex", HTTP_OLD, ["requests==2.31.0"])),
        read_pex(make_pex("new.pex", HTTP_NEW, ["requests==2.32.3", "httpx"])),
    )
    kinds = {c.project: c.change for c in d.changed}
    assert kinds == {
        "requests": Change.upgraded,
        "httpx": Change.added,
        "httpcore": Change.added,
        "h11": Change.added,
    }
    h11 = next(c for c in d.changed if c.project == "h11")
    assert h11.why == [["httpx", "httpcore", "h11"]]
    req = next(c for c in d.changed if c.project == "requests")
    assert not req.license_changed  # "Apache 2.0" vs "Apache-2.0"
    assert d.delta > 0
    assert "requirements" in d.info_changes


def test_diff_detects_lost_platform(make_pex):
    good = [("pyqt6_qt6-6.11.2-py3-none-macosx_10_14_universal2.whl", [], None, 10)] + QT[::2]
    d = diff_pex(read_pex(make_pex("good.pex", good)), read_pex(make_pex("bad.pex", QT)))
    assert d.platforms_lost == {("macos", "arm64")}
    qt6 = next(c for c in d.changed if c.project == "pyqt6-qt6")
    assert qt6.change is Change.rebuilt


# ---------------------------------------------------------------------------- CLI


runner = CliRunner()


def test_cli_info_json(make_pex):
    r = runner.invoke(app, ["info", str(make_pex("qt.pex", QT, ["PyQt6"])), "-f", "json"])
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["runs_on"] == {"platforms": ["macos/x86_64"], "python": ["3.12"]}
    assert {f["code"] for f in data["findings"]} >= {"platform-gap"}


def test_cli_info_rich_and_why(make_pex):
    path = str(make_pex("http.pex", HTTP_NEW, ["requests", "httpx"]))
    r = runner.invoke(app, ["info", path])
    assert r.exit_code == 0, r.output
    assert "httpcore" in r.stdout
    r = runner.invoke(app, ["why", path, "h11"])
    assert r.exit_code == 0 and "httpcore" in r.stdout


def test_cli_diff_markdown(make_pex):
    r = runner.invoke(
        app,
        ["diff", str(make_pex("old.pex", HTTP_OLD)), str(make_pex("new.pex", HTTP_NEW)), "-f", "markdown"],
    )
    assert r.exit_code == 0, r.output
    assert "| + added | `httpx` |" in r.stdout
    assert "<details>" in r.stdout


def test_cli_bad_file(tmp_path):
    f = tmp_path / "x.pex"
    f.write_text("nope")
    r = runner.invoke(app, ["info", str(f)])
    assert r.exit_code == 2
