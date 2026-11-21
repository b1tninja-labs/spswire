"""ROADMAP rows stay honest: a done or partial row names a test that exists."""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TEST_REF = re.compile(r"([\w./-]+\.py)((?:::\w+)+)")
TO_BE_WRITTEN = "(to be written)"


def _cells(line: str) -> list[str]:
    bars = [i for i, ch in enumerate(line) if ch == "|" and (i == 0 or line[i - 1] != "\\")]
    return [line[bars[k] + 1 : bars[k + 1]].strip() for k in range(len(bars) - 1)]


def _rows() -> list[tuple[str, str, str]]:
    lines = (ROOT / "ROADMAP.md").read_text(encoding="utf-8").splitlines()
    found: list[tuple[str, str, str]] = []
    index = 0
    while index < len(lines):
        if not lines[index].startswith("|"):
            index += 1
            continue
        start = index
        while index < len(lines) and lines[index].startswith("|"):
            index += 1
        table = lines[start:index]
        if len(table) < 3:
            continue
        header = [cell.lower() for cell in _cells(table[0])]
        if not header or header[0] != "obligation" or "status" not in header:
            continue
        status_at = header.index("status")
        where_at = header.index("where") if "where" in header else None
        for line in table[2:]:
            cells = _cells(line)
            if len(cells) <= status_at:
                continue
            where = cells[where_at] if where_at is not None and where_at < len(cells) else ""
            found.append((cells[0], cells[status_at].strip(), where))
    return found


def _defines(path: Path, function: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == function
        for node in tree.body
    )


def test_dependencies_stay_empty():
    parsed = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if parsed["project"]["dependencies"] != [] or "build-system" in parsed:
        pytest.fail("spswire gained a dependency or a build backend")


def test_partial_and_done_rows_name_a_test_that_exists():
    missing: list[str] = []
    present: list[str] = []
    for name, status, where in _rows():
        for found in TEST_REF.finditer(where):
            window = re.split(r"[,;]", where[found.end() :], maxsplit=1)[0]
            relative = found.group(1)
            function = found.group(2).split("::")[-1]
            path = ROOT / relative
            if TO_BE_WRITTEN in window:
                if path.exists():
                    present.append(relative)
                continue
            if status in {"[ok]", "[part]"} and (
                not path.is_file()
                or not function.startswith("test")
                or not _defines(path, function)
            ):
                missing.append(f"{name} -> {relative}::{function}")
        if (
            status in {"[ok]", "[part]"}
            and TO_BE_WRITTEN not in where
            and not TEST_REF.search(where)
        ):
            missing.append(f"{name} names no test")
        if status == "[ ]" and TO_BE_WRITTEN not in where:
            missing.append(f"{name} is open but its test is not marked to be written")
    if missing or present:
        pytest.fail(
            "roadmap tests drifted:\n"
            + "\n".join(
                [*missing, *(f"{item} exists but is marked to be written" for item in present)]
            )
        )
