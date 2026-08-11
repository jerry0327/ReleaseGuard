from __future__ import annotations

import json
import subprocess
from typing import Any

from .models import Change


def _git(args: list[str], *, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def rev_parse(ref: str) -> str:
    return _git(["rev-parse", ref]).strip()


def resolve_default_range() -> tuple[str, str]:
    head = rev_parse("HEAD")
    try:
        base = rev_parse("HEAD^")
    except RuntimeError as exc:
        raise RuntimeError("could not infer a base commit; pass --base and --head") from exc
    return base, head


def _parse_numstat(base: str, head: str) -> set[str]:
    binary: set[str] = set()
    for line in _git(["diff", "--numstat", f"{base}...{head}"]).splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        added, deleted = parts[0], parts[1]
        path = parts[-1]
        if added == "-" and deleted == "-":
            binary.add(path)
    return binary


def _parse_modes(base: str, head: str) -> dict[str, tuple[str | None, str | None]]:
    modes: dict[str, tuple[str | None, str | None]] = {}
    for line in _git(["diff", "--raw", "--find-renames", f"{base}...{head}"]).splitlines():
        if not line.startswith(":") or "\t" not in line:
            continue
        meta, names = line.split("\t", 1)
        fields = meta[1:].split()
        if len(fields) < 5:
            continue
        old_mode, new_mode = fields[0], fields[1]
        paths = names.split("\t")
        path = paths[-1]
        modes[path] = (old_mode, new_mode)
    return modes


def get_changes(base: str, head: str) -> list[Change]:
    binary_paths = _parse_numstat(base, head)
    modes = _parse_modes(base, head)
    changes: list[Change] = []

    for line in _git(["diff", "--name-status", "--find-renames", f"{base}...{head}"]).splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        old_path: str | None = None
        path = parts[-1]
        if status.startswith("R") and len(parts) >= 3:
            old_path = parts[1]
        old_mode, new_mode = modes.get(path, (None, None))
        changes.append(
            Change(
                path=path,
                status=status,
                old_path=old_path,
                is_binary=path in binary_paths,
                old_mode=old_mode,
                new_mode=new_mode,
            )
        )
    return changes


def read_text_at_ref(ref: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def read_json_at_ref(ref: str, path: str) -> dict[str, Any] | None:
    raw = read_text_at_ref(ref, path)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None
