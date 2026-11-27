# SPDX-License-Identifier: AGPL-3.0-or-later
"""The model folders: where the containers look for .igz files, and which
of them the MCP service may write to.

Without ``MODEL_FOLDERS`` there is one folder, the data folder itself
(``/data``), named ``data``, read/write: as before there were folders.

``MODEL_FOLDERS`` lists folders under the data folder, one per entry,
entries separated by ``;`` or new lines::

    MODEL_FOLDERS="projects:rw; archive:ro:depth=1:exclude=old*,*.bak"

Each entry is ``name[:mode][:depth=N][:exclude=glob,glob…]``:

- ``name``: the folder ``/data/<name>`` (bind-mount the host folder there);
  also the path prefix MCP clients use (``projects/house.igz``) and the
  heading in the viewer. Letters, digits, ``.``, ``_`` and ``-``.
- ``mode``: ``rw`` (default) or ``ro``. ``ro`` refuses saving and exporting
  into the folder. Only the MCP service writes at all: the viewer mounts
  everything read-only.
- ``depth``: how deep to look for models: ``0`` the folder itself only,
  ``1`` one level of subfolders, … Default: no limit (``MODEL_SCAN_DEPTH``).
- ``exclude``: glob patterns of files and folders to leave out of the
  listing (``MODEL_EXCLUDE`` for every folder). A pattern without ``/``
  matches a file or folder name at any depth (``*.bak``, ``archive*``);
  one with ``/`` matches the path from the folder's root
  (``old/**``, ``2023/*.igz``). ``**`` spans folders, ``*`` does not.
  Excluded files can still be opened by path; they are only not listed.

Folders and files whose name starts with ``.`` are never listed.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(os.environ.get("INGETRAZO_DATA", "/data")).resolve()
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def glob_re(pattern: str) -> re.Pattern:
    """A glob as a regular expression on a /-separated relative path."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out) + r"\Z")


@dataclass
class Folder:
    name: str
    root: Path
    writable: bool = True
    depth: int | None = None                 # None: no limit
    exclude: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._anywhere = [glob_re(p) for p in self.exclude if "/" not in p.strip("/")]
        self._anchored = [glob_re(p.strip("/")) for p in self.exclude if "/" in p.strip("/")]

    @property
    def mode(self) -> str:
        return "rw" if self.writable else "ro"

    def excluded(self, rel: str) -> bool:
        """``rel``: a file's or folder's path from the root, /-separated."""
        parts = rel.split("/")
        if any(p.startswith(".") for p in parts):
            return True
        if any(r.match(p) for r in self._anywhere for p in parts):
            return True
        # A folder that matches takes everything below it along.
        return any(r.match("/".join(parts[:n])) for r in self._anchored
                   for n in range(1, len(parts) + 1))

    def models(self) -> list[Path]:
        """The folder's .igz files, as deep as ``depth`` goes, without the
        excluded ones; folders that are left out are not walked at all."""
        if not self.root.is_dir():
            return []
        out = []
        for here, dirs, files in os.walk(self.root):
            rel_dir = Path(here).relative_to(self.root).as_posix()
            level = 0 if rel_dir == "." else rel_dir.count("/") + 1
            prefix = "" if rel_dir == "." else rel_dir + "/"
            if self.depth is not None and level >= self.depth:
                dirs[:] = []
            else:
                dirs[:] = sorted(d for d in dirs if not self.excluded(prefix + d))
            for f in files:
                if f.lower().endswith(".igz") and not self.excluded(prefix + f):
                    p = Path(here) / f
                    if p.is_file():
                        out.append(p)
        return sorted(out)

    def contains(self, p: Path) -> bool:
        return p == self.root or self.root in p.parents

    def describe(self) -> str:
        extra = ""
        if self.depth is not None:
            extra += f", depth {self.depth}"
        if self.exclude:
            extra += ", exclude " + " ".join(self.exclude)
        return f"{self.name} ({self.root}, {self.mode}{extra})"


def _int(value: str, what: str) -> int | None:
    value = value.strip()
    if value in ("", "-1", "all", "none"):
        return None
    if not value.isdigit():
        raise ValueError(f"{what}: depth must be a number, 0 or more: {value!r}")
    return int(value)


def _globs(value: str) -> list[str]:
    return [g.strip() for g in value.split(",") if g.strip()]


def parse(spec: str, default_depth: int | None = None,
          default_exclude: list[str] | None = None,
          data_dir: Path = DATA_DIR) -> list[Folder]:
    """``MODEL_FOLDERS`` as a list of folders; empty: the data folder."""
    default_exclude = list(default_exclude or [])
    entries = [e.strip() for e in re.split(r"[;\n]", spec or "") if e.strip()]
    if not entries:
        return [Folder("data", data_dir, True, default_depth, default_exclude)]
    folders: list[Folder] = []
    for entry in entries:
        name, *opts = [p.strip() for p in entry.split(":")]
        if not _NAME.match(name):
            raise ValueError(f"MODEL_FOLDERS: not a folder name: {name!r} "
                             "(letters, digits, '.', '_' and '-')")
        if any(f.name == name for f in folders):
            raise ValueError(f"MODEL_FOLDERS: {name!r} is listed twice")
        writable, depth, exclude = True, default_depth, list(default_exclude)
        for opt in opts:
            key, eq, value = opt.partition("=")
            key = key.strip().lower()
            if not eq and key in ("rw", "ro"):
                writable = key == "rw"
            elif eq and key == "depth":
                depth = _int(value, f"MODEL_FOLDERS {name}")
            elif eq and key == "exclude":
                exclude += _globs(value)
            elif opt:
                raise ValueError(f"MODEL_FOLDERS {name}: unknown option {opt!r} "
                                 "(rw, ro, depth=N, exclude=glob,glob)")
        folders.append(Folder(name, (data_dir / name).resolve(), writable, depth, exclude))
    return folders


def from_env() -> list[Folder]:
    """The folders as configured; a mistake stops the service with a
    message that names it."""
    try:
        return parse(os.environ.get("MODEL_FOLDERS", ""),
                     _int(os.environ.get("MODEL_SCAN_DEPTH", ""), "MODEL_SCAN_DEPTH"),
                     _globs(os.environ.get("MODEL_EXCLUDE", "")))
    except ValueError as exc:
        raise SystemExit(f"[ingetrazo-web-viewer] {exc}") from None


FOLDERS: list[Folder] = from_env()


def folder_of(p: Path) -> Folder | None:
    """The folder a path lies in (the innermost, should they nest)."""
    hits = [f for f in FOLDERS if f.contains(p)]
    return max(hits, key=lambda f: len(f.root.parts)) if hits else None


def list_models() -> list[tuple[Folder, Path]]:
    """Every listed model, folder by folder in the configured order."""
    return [(f, p) for f in FOLDERS for p in f.models()]


def display_name(p: Path) -> str:
    """A model's path from the data folder, /-separated: what MCP clients
    pass and the viewer shows."""
    return p.relative_to(DATA_DIR).as_posix()


def _names() -> str:
    return ", ".join(f"{f.name} ({f.mode})" for f in FOLDERS)


def resolve(value: str, write: bool = False, must_exist: bool = False) -> Path:
    """A path an agent gave, relative to the data folder or absolute inside
    it, in one of the model folders; for ``write``, a read/write one."""
    p = Path(value).expanduser()
    if not p.is_absolute():
        p = DATA_DIR / p
    p = p.resolve()
    if p != DATA_DIR and DATA_DIR not in p.parents:
        raise PermissionError(f"outside the data folder {DATA_DIR}: {value}")
    folder = folder_of(p)
    if folder is None:
        raise PermissionError(f"not in a model folder: {value}. The folders "
                              f"are: {_names()}; e.g. {FOLDERS[0].name}/<file>")
    if write and not folder.writable:
        rw = [f.name for f in FOLDERS if f.writable]
        raise PermissionError(
            f"the folder {folder.name!r} is read-only: cannot write {value}. "
            + (f"Read/write: {', '.join(rw)}." if rw else "No folder is read/write."))
    if must_exist and not p.is_file():
        raise FileNotFoundError(f"no such file in {folder.root}: {value}")
    return p
