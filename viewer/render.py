# SPDX-License-Identifier: AGPL-3.0-or-later
"""Renders the models of the model folders, on demand, and keeps what it
rendered.

Read-only headless IngeTrazos in render engines (``ENGINE_URLS``, one
render worker per engine) do the work, each one task at a time, all from
one queue with priorities:

1. ``NOW``: what a user is waiting for: the model's listing, the sheet or
   view on screen, the 3D model, the PDF they asked for;
2. ``NEXT``: the neighbours of what is on screen (prev/next), and the items
   viewed in the last ``VIEWER_RECENT_MINUTES`` after their model changed;
3. ``PREVIEW``: one small preview per model for the overview;
4. ``BACKGROUND``: everything else, with ``VIEWER_PRERENDER=all``: the
   saved views first, then the sheets, then the 3D model;
5. ``LAST``: with ``VIEWER_PRERENDER=all``, the PDF of all sheets (one long
   call that nothing can interrupt), once nothing else is waiting.

Per model, a **listing** (open the file, read its sheets, saved views and
their folders, and the views' cameras: cheap) goes to
``/cache/<slug>/index.json``. Each rendered item goes to
``/cache/<slug>/<rev>/``, its file name carrying the render settings:
``sheet-003-120dpi.png``, ``view-002-1600x1000.png``, ``preview-….png``,
``sheets.pdf``, ``model.glb``. ``<rev>`` is new for every listing, so the
URLs change when the model does and a browser may cache them for good.

When a model file changes (modification time or size, and it has stayed
put for ``VIEWER_SETTLE_SECONDS``), its renders are not redone: the next
listing starts a new rev, and the items are rendered again when someone
looks at them. The previous rev is kept until the one after, so a page
shows the old picture while the new one renders.

``VIEWER_PRERENDER``: ``previews`` (default) lists every model and renders
its preview in the background; ``none`` renders only what is asked for
(the overview's previews when it is opened); ``all`` renders everything in
the background, as the viewer did before.
"""
from __future__ import annotations

import collections
import copy
import hashlib
import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from mcp_http import folders
from mcp_http.common import DATA_DIR, log
from mcp_http.remote import RemoteApp

CACHE_DIR = Path(os.environ.get("INGETRAZO_CACHE", "/cache"))
POLL = float(os.environ.get("VIEWER_POLL_SECONDS", 3))
SETTLE = float(os.environ.get("VIEWER_SETTLE_SECONDS", 2))
RETRY = float(os.environ.get("VIEWER_RETRY_SECONDS", 120))   # a failed render, again
SHEET_DPI = int(os.environ.get("VIEWER_SHEET_DPI", 120))
VIEW_W = int(os.environ.get("VIEWER_VIEW_WIDTH", 1600))
VIEW_H = int(os.environ.get("VIEWER_VIEW_HEIGHT", 1000))
PREVIEW_DPI = int(os.environ.get("VIEWER_PREVIEW_DPI", 36))
PREVIEW_W = int(os.environ.get("VIEWER_PREVIEW_WIDTH", 480))
PREVIEW_H = int(os.environ.get("VIEWER_PREVIEW_HEIGHT", 300))
WITH_PDF = os.environ.get("VIEWER_PDF", "1").strip().lower() not in ("0", "false", "no", "off")
#: The 3D model (GLB) for the browser's 3D view: one bigger than this many
#: MB is not offered (0 = no 3D view at all).
GLB_MAX_MB = float(os.environ.get("VIEWER_GLB_MAX_MB", 50) or 0)
PRERENDER = os.environ.get("VIEWER_PRERENDER", "previews").strip().lower() or "previews"
if PRERENDER not in ("all", "previews", "none"):
    raise SystemExit(f"VIEWER_PRERENDER must be all, previews or none, not {PRERENDER!r}")
RECENT = float(os.environ.get("VIEWER_RECENT_MINUTES", 30)) * 60



#: Bumped when index.json changes shape: a model listed by an older viewer
#: is listed again, even though its file is unchanged.
INDEX_FORMAT = 5

NOW, NEXT, PREVIEW, BACKGROUND, LAST = 0, 1, 2, 3, 4


def slug_of(model: Path) -> str:
    rel = model.relative_to(DATA_DIR).as_posix()
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", rel[:-4] if rel.endswith(".igz") else rel)
    return f"{base.strip('-')[:60]}-{hashlib.sha1(rel.encode()).hexdigest()[:6]}"


def _signature(model: Path) -> list:
    st = model.stat()
    return [st.st_mtime_ns, st.st_size]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path(folder) -> list[str]:
    """A folder as the app reports it ("A/B", a list, or nothing) as a list
    of names, top first."""
    if isinstance(folder, (list, tuple)):
        return [str(p) for p in folder if str(p).strip()]
    return [p for p in str(folder or "").split("/") if p.strip()]


def item_file(item: str) -> str:
    """An item's file name in a rev folder; it names the render settings,
    so other settings never pick up an older picture."""
    kind, _, n = item.partition(":")
    if kind == "sheet":
        return f"sheet-{int(n):03d}-{SHEET_DPI}dpi.png"
    if kind == "view":
        return f"view-{int(n):03d}-{VIEW_W}x{VIEW_H}.png"
    if kind == "preview":
        return f"preview-{PREVIEW_DPI}dpi-{PREVIEW_W}x{PREVIEW_H}.png"
    return {"pdf": "sheets.pdf", "glb": "model.glb"}[kind]


_MARK = "@@itz-viewer@@"
#: Read-only: each saved view's folder path, walking the Scenes tab's
#: nesting (core.scene_folders). Runs in a function so it leaves nothing
#: behind in the app's Python scope.
_SCENE_FOLDERS = f"""
def _itz_viewer_paths():
    import json
    from core import scene_folders as sf
    out = {{}}
    for v in scene.saved_views:
        path, f, seen = [], sf.folder_of(scene, v), set()
        while f and f not in seen:
            seen.add(f)
            path.insert(0, f)
            f = sf.folder_parent(scene, f)
        out[v.name] = path
    print({_MARK!r} + json.dumps(out, ensure_ascii=False))
_itz_viewer_paths()
del _itz_viewer_paths
"""

#: Read-only: each saved view's camera (core.saved_views.SavedView, the
#: orbit camera's own terms: target, distance, yaw, pitch, fov), for the
#: 3D view's camera presets.
_SCENE_CAMERAS = f"""
def _itz_viewer_cameras():
    import json
    out = []
    for v in scene.saved_views:
        out.append({{"name": v.name, "target": [float(c) for c in v.target],
                    "distance": float(v.distance), "yaw": float(v.yaw),
                    "pitch": float(v.pitch), "fov": float(v.fov_deg),
                    "perspective": bool(v.perspective),
                    "hidden_layers": [str(n) for n in
                                      getattr(v, "hidden_layers", None) or ()]}})
    print({_MARK!r} + json.dumps(out, ensure_ascii=False))
_itz_viewer_cameras()
del _itz_viewer_cameras
"""

#: Read-only: the layers' tree as the Layers panel shows it
#: (core.layers): each folder with the folder it sits in, each layer with
#: its folder, for the 3D view's Layers panel.
_SCENE_LAYERS = f"""
def _itz_viewer_layers():
    import json
    from core import layers as L
    folders = [{{"name": f, "parent": L.folder_parent(scene, f)}}
               for f in L.folders_of(scene)]
    out = {{"folders": folders,
           "layers": {{ly.name: getattr(ly, "folder", None) for ly in scene.layers}}}}
    print({_MARK!r} + json.dumps(out, ensure_ascii=False))
_itz_viewer_layers()
del _itz_viewer_layers
"""


@dataclass
class Model:
    slug: str
    path: Path
    folder: folders.Folder
    name: str                    # from the data folder: what the MCP side calls it
    rel: str                     # from its model folder


@dataclass
class _Worker:
    """One render thread and the IngeTrazo it drives."""
    n: int
    app: object
    open: tuple[str, str] | None = None     # (slug, rev) open in its app
    dirty: bool = False                     # a render changed the view
    rendering: tuple[str, str] | None = None


@dataclass
class _Task:
    priority: int
    seq: int
    not_before: float


class RenderQueue:
    """Tasks ``(slug, item)``, each at most once, at its most urgent
    priority. ``pop`` takes the most urgent; among equals, one of the model
    that is open already (switching models costs an open_document), then
    the oldest."""

    def __init__(self) -> None:
        self.cv = threading.Condition()
        self.tasks: dict[tuple[str, str], _Task] = {}
        self._seq = 0

    def put(self, slug: str, item: str, priority: int, delay: float = 0.0) -> None:
        with self.cv:
            key = (slug, item)
            t = self.tasks.get(key)
            if t is None:
                self._seq += 1
                self.tasks[key] = _Task(priority, self._seq, time.monotonic() + delay)
            elif priority < t.priority:
                t.priority = priority
                t.not_before = min(t.not_before, time.monotonic() + delay)
            self.cv.notify()

    def pop(self, prefer: str | None) -> tuple[str, str, int]:
        with self.cv:
            while True:
                now = time.monotonic()
                ready = [(k, t) for k, t in self.tasks.items() if t.not_before <= now]
                if ready:
                    top = min(t.priority for _, t in ready)
                    best = min((kt for kt in ready if kt[1].priority == top),
                               key=lambda kt: (kt[0][0] != prefer, kt[1].seq))
                    del self.tasks[best[0]]
                    return best[0][0], best[0][1], best[1].priority
                later = [t.not_before - now for t in self.tasks.values()]
                self.cv.wait(timeout=min(later) if later else None)

    def pending(self, slug: str) -> set[str]:
        with self.cv:
            return {i for (s, i) in self.tasks if s == slug}

    def empty(self) -> bool:
        with self.cv:
            return not self.tasks


class Renderer:
    def __init__(self, apps: RemoteApp | list[RemoteApp]) -> None:
        self.apps = list(apps) if isinstance(apps, (list, tuple)) else [apps]
        self.app = self.apps[0]
        self.workers = [_Worker(i + 1, a) for i, a in enumerate(self.apps)]
        self._local = threading.local()          # the worker of this thread
        self._write = threading.RLock()          # index.json read-modify-write
        self._listing: dict[str, threading.Lock] = collections.defaultdict(threading.Lock)
        self.queue = RenderQueue()
        self.changed = threading.Condition()
        self.generation = 0          # bumped on every event
        self.events: collections.deque = collections.deque(maxlen=256)
        self.heartbeat = time.monotonic()
        self._models: dict[str, Model] = {}
        self._index: dict[str, dict] = {}
        self._index_lock = threading.Lock()
        self._recent: dict[tuple[str, str, str], float] = {}
        self._refresh_models()

    # ---- the workers ---------------------------------------------------------
    @property
    def _w(self) -> _Worker:
        """The worker of the calling thread (the first one elsewhere)."""
        return getattr(self._local, "w", None) or self.workers[0]

    @property
    def _open(self) -> tuple[str, str] | None:
        return self._w.open

    @_open.setter
    def _open(self, value: tuple[str, str] | None) -> None:
        self._w.open = value

    @property
    def _dirty(self) -> bool:
        return self._w.dirty

    @_dirty.setter
    def _dirty(self, value: bool) -> None:
        self._w.dirty = value

    @property
    def rendering(self) -> tuple[str, str] | None:
        """What a worker renders now (the first busy one), or None."""
        for w in self.workers:
            if w.rendering:
                return w.rendering
        return None

    def busy_slugs(self) -> set[str]:
        return {w.rendering[0] for w in self.workers if w.rendering}

    def alive(self) -> bool:
        return all(a.alive() for a in self.apps)

    # ---- the models --------------------------------------------------------
    def _refresh_models(self) -> bool:
        """Re-reads the model folders; True when the set of models changed."""
        found = {}
        for folder, path in folders.list_models():
            slug = slug_of(path)
            found[slug] = Model(slug, path, folder, folders.display_name(path),
                                path.relative_to(folder.root).as_posix())
        changed = set(found) != set(self._models)
        self._models = found
        return changed

    def model(self, slug: str) -> Model | None:
        return self._models.get(slug)

    def models(self) -> list[dict]:
        """For the overview: every model, folder by folder."""
        busy = self.busy_slugs()
        out = []
        for m in list(self._models.values()):
            out.append({"slug": m.slug, "name": m.name, "rel": m.rel,
                        "folder": m.folder.name, "mode": m.folder.mode,
                        "index": self.index(m.slug) or {},
                        "fresh": self.fresh(m.slug),
                        "rendering": m.slug in busy})
        return out

    def status(self) -> list[dict]:
        """For the admin's render list (``/admin/renders``): every model with
        each saved view, sheet, 3D model and PDF and how far its render is:
        ``rendered``, ``outdated`` (rendered, but the model changed since),
        ``rendering``, ``queued``, ``failed``, ``skipped`` or ``missing``."""
        busy = {w.rendering for w in self.workers if w.rendering}
        out = []
        for m in sorted(self._models.values(),
                        key=lambda m: (m.folder.name.casefold(), m.rel.casefold())):
            idx, fresh = self.index(m.slug), self.fresh(m.slug)
            pending = self.queue.pending(m.slug)
            entry = {"slug": m.slug, "name": m.name, "folder": m.folder.name,
                     "rel": m.rel, "fresh": fresh, "listed": idx is not None,
                     "listing": (m.slug, "list") in busy or "list" in pending,
                     "errors": list((idx or {}).get("errors") or []), "items": []}
            for item in (self._items(idx) if idx else []):
                if item == "preview":
                    continue
                kind, _, n = item.partition(":")
                e = {"item": item, "kind": kind, "name": {"glb": "3D model", "pdf": "PDF"}.get(kind, ""),
                     "folder": []}
                if kind in ("view", "sheet"):
                    src = (idx.get(kind + "s") or [])[int(n) - 1]
                    e["name"], e["folder"] = src.get("name", ""), _path(src.get("folder"))
                st = self.state(idx, item)
                if (m.slug, item) in busy:
                    e["status"] = "rendering"
                elif st.get("file"):
                    e["status"] = "rendered" if fresh else "outdated"
                elif st.get("note"):
                    e["status"], e["detail"] = "skipped", st["note"]
                elif st.get("error"):
                    e["status"], e["detail"] = "failed", st["error"]
                elif item in pending or "all" in pending:
                    e["status"] = "queued"
                else:
                    e["status"] = "missing"
                if st.get("seconds") is not None and e["status"] in ("rendered", "outdated"):
                    e["seconds"] = st["seconds"]
                if st.get("at"):
                    e["at"] = st["at"]
                entry["items"].append(e)
            out.append(entry)
        return out

    # ---- the listings --------------------------------------------------------
    def index(self, slug: str) -> dict | None:
        """The model's latest listing (never to be changed by the caller)."""
        with self._index_lock:
            idx = self._index.get(slug)
        if idx is not None:
            return idx
        try:
            idx = json.loads((CACHE_DIR / slug / "index.json").read_text("utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(idx, dict) or idx.get("format") != INDEX_FORMAT:
            return None
        with self._index_lock:
            self._index.setdefault(slug, idx)
        return idx

    def _save(self, idx: dict) -> None:
        with self._write:
            base = CACHE_DIR / idx["slug"]
            base.mkdir(parents=True, exist_ok=True)
            tmp = base / "index.json.part"
            tmp.write_text(json.dumps(idx, indent=1, ensure_ascii=False), "utf-8")
            tmp.replace(base / "index.json")
            with self._index_lock:
                self._index[idx["slug"]] = copy.deepcopy(idx)

    def _set_item(self, slug: str, rev: str, item: str, state: dict) -> bool:
        """One item's state into the model's current listing; False (and
        nothing saved) when a newer listing replaced ``rev`` meanwhile.
        Read and written under one lock: workers finish items of the same
        model at the same time."""
        with self._write:
            idx = copy.deepcopy(self.index(slug))
            if idx is None or idx.get("rev") != rev:
                return False
            idx.setdefault("items", {})[item] = state
            self._save(idx)
            return True

    def fresh(self, slug: str) -> bool:
        """The listing describes the file as it is now (a failed listing
        counts as fresh until ``VIEWER_RETRY_SECONDS`` have passed)."""
        m, idx = self._models.get(slug), self.index(slug)
        if m is None or idx is None:
            return False
        try:
            sig = _signature(m.path)
        except OSError:
            return True                     # gone: nothing to list
        if idx.get("source_signature") != sig:
            return False
        return not (idx.get("errors") and time.time() - idx.get("listed_ts", 0) > RETRY)

    def state(self, idx: dict, item: str) -> dict:
        """An item's render: ``file`` (rendered), ``error``, ``note``,
        ``warnings``; empty when it was not rendered yet."""
        return (idx.get("items") or {}).get(item) or {}

    def due(self, idx: dict, item: str) -> bool:
        """Not rendered, and not failed a moment ago."""
        st = self.state(idx, item)
        if st.get("file") or st.get("note"):
            return False
        return not st.get("error") or time.time() - st.get("at", 0) > RETRY

    # ---- what the pages ask for ----------------------------------------------
    def request(self, slug: str, item: str, priority: int = NOW) -> None:
        if slug in self._models:
            self.queue.put(slug, item, priority)

    def viewed(self, slug: str, item: str, name: str) -> None:
        """A sheet or view was looked at: rendered again first after its
        model changes (by name: its place may change)."""
        now = time.time()
        self._recent[(slug, item.partition(":")[0], name)] = now
        for k, t in list(self._recent.items()):
            if now - t > RECENT:
                self._recent.pop(k, None)

    def _notify(self, kind: str, **event) -> None:
        with self.changed:
            self.generation += 1
            self.events.append({**event, "kind": kind, "generation": self.generation})
            self.changed.notify_all()

    def events_since(self, generation: int) -> list[dict]:
        with self.changed:
            return [e for e in self.events if e["generation"] > generation]

    # ---- the loops -----------------------------------------------------------
    def run(self) -> None:
        """Starts the render worker, then watches the model folders."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        for w in self.workers:
            threading.Thread(target=self._work, args=(w,), daemon=True,
                             name="render" if len(self.workers) == 1 else f"render-{w.n}").start()
        while True:
            self.heartbeat = time.monotonic()
            try:
                self._scan()
            except Exception as exc:                 # keep watching
                log(f"viewer: scan failed: {exc!r}")
            time.sleep(POLL)

    def _scan(self) -> None:
        if self._refresh_models():
            self._notify("models")
        for m in list(self._models.values()):
            idx = self.index(m.slug)
            if PRERENDER == "none":
                continue
            if not self.fresh(m.slug) or idx is None:
                # The preview first (it lists the model), for every model,
                # before the rest of any of them.
                self.queue.put(m.slug, "preview", PREVIEW)
                if PRERENDER == "all":
                    self.queue.put(m.slug, "all", BACKGROUND)
            elif PRERENDER == "all":
                if self.due(idx, "preview"):
                    self.queue.put(m.slug, "preview", PREVIEW)
                if any(self.due(idx, i) for i in self._items(idx)):
                    self.queue.put(m.slug, "all", BACKGROUND)
            elif self.due(idx, "preview"):
                self.queue.put(m.slug, "preview", PREVIEW)
        # Models that are gone: their renders go too.
        for d in CACHE_DIR.iterdir() if CACHE_DIR.is_dir() else ():
            if d.is_dir() and d.name not in self._models:
                shutil.rmtree(d, ignore_errors=True)
                with self._index_lock:
                    self._index.pop(d.name, None)
                self._notify("removed", slug=d.name)

    def _work(self, worker: _Worker | None = None) -> None:
        w = worker or self.workers[0]
        self._local.w = w
        while True:
            slug, item, priority = self.queue.pop(w.open[0] if w.open else None)
            w.rendering = (slug, item)
            self._notify("rendering", slug=slug, item=item)
            try:
                self._task(slug, item, priority)
            except Exception as exc:                 # keep working
                log(f"viewer: {slug} {item}: {exc!r}")
            finally:
                w.rendering = None
            if self.queue.empty() and self.rendering is None:
                self._notify("idle")

    def _items(self, idx: dict) -> list[str]:
        """Every item of a model, in the order ``all`` renders them: what
        people open most first (the saved views), then the sheets, the 3D
        model (it reopens the document as saved) and the PDF."""
        n_sheets, n_views = len(idx.get("sheets") or []), len(idx.get("views") or [])
        items = ["preview"] + [f"view:{i}" for i in range(1, n_views + 1)]
        items += [f"sheet:{i}" for i in range(1, n_sheets + 1)]
        if GLB_MAX_MB > 0:
            items.append("glb")
        if WITH_PDF and n_sheets:
            items.append("pdf")
        return items

    @staticmethod
    def _background(item: str) -> int:
        """The priority of an item that ``all`` renders unasked."""
        return {"preview": PREVIEW, "pdf": LAST}.get(item, BACKGROUND)

    def _task(self, slug: str, item: str, priority: int) -> None:
        m = self._models.get(slug)
        if m is None:
            return
        try:
            sig = _signature(m.path)
        except OSError:
            return
        if not self.fresh(slug):
            if time.time() - sig[0] / 1e9 < SETTLE:   # still being written
                self.queue.put(slug, item, priority, delay=SETTLE)
                return
            with self._listing[slug]:                # one worker lists it
                if not self.fresh(slug):
                    self._list(m, sig)
        if item == "list":
            return
        idx = copy.deepcopy(self.index(slug))
        if idx is None:
            return
        if item == "all":
            for i in self._items(idx):
                if self.due(idx, i):
                    self.queue.put(slug, i, self._background(i))
            return
        if item not in self._items(idx) or not self.due(idx, item):
            return
        if idx.get("errors"):                        # the file did not open
            self._set_item(slug, idx["rev"], item, {"error": "; ".join(idx["errors"]),
                                                    "at": time.time()})
            self._notify("done", slug=slug, rev=idx["rev"], item=item, ok=False)
            return
        self._render(m, idx, item)

    # ---- listing ---------------------------------------------------------------
    def _call(self, tool: str, args: dict | None = None) -> dict:
        reply = self._w.app.call(tool, args or {})
        if not reply.get("ok"):
            raise RuntimeError(f"{tool}: {reply.get('error')}")
        return reply.get("result") or {}

    def _open_model(self, m: Model, rev: str, clean: bool = False) -> None:
        """The model open in the app; ``clean``: as saved, nothing a render
        changed (rendering a saved view switches layers on and off)."""
        if self._open == (m.slug, rev) and not (clean and self._dirty):
            return
        self._open = None
        # The viewer never saves: whatever a render left changed goes.
        self._call("open_document", {"path": str(m.path), "discard_changes": True})
        self._open, self._dirty = (m.slug, rev), False

    def _list(self, m: Model, sig: list) -> None:
        log(f"viewer: listing {m.name}")
        t0 = time.monotonic()
        old = self.index(m.slug)
        rev = f"r{time.time_ns() // 1_000_000}"
        idx = {"format": INDEX_FORMAT, "name": m.name, "folder": m.folder.name,
               "slug": m.slug, "rev": rev, "source_signature": sig,
               "listed_at": _now(), "listed_ts": time.time(),
               "sheets": [], "views": [], "cameras": [], "items": {}, "errors": []}
        try:
            self._open = None
            info = self._call("open_document", {"path": str(m.path),
                                                "discard_changes": True})
            self._open, self._dirty = (m.slug, rev), False
            idx["sheets"] = self._sheet_list(info)
            views = [str(v) for v in info.get("views") or []]
            paths = self._view_folders() if views else {}
            idx["views"] = [{"name": v, "folder": paths.get(v, [])} for v in views]
            if GLB_MAX_MB > 0 and views:
                idx["cameras"] = self._view_cameras()
            if GLB_MAX_MB > 0:
                idx["layer_tree"] = self._layer_tree()
        except Exception as exc:
            idx["errors"].append(str(exc))
            log(f"viewer: {m.name}: {exc}")
        idx["list_seconds"] = round(time.monotonic() - t0, 1)
        # The last rev's pictures stay until the next listing: a page shows
        # them while the new ones render.
        idx["prev"] = self._prev_files(old) if old else None
        (CACHE_DIR / m.slug / rev).mkdir(parents=True, exist_ok=True)
        self._save(idx)
        keep = {rev} | ({idx["prev"]["rev"]} if idx["prev"] else set())
        for d in (CACHE_DIR / m.slug).iterdir():
            if d.is_dir() and d.name not in keep:
                shutil.rmtree(d, ignore_errors=True)
        log(f"viewer: {m.name}: {len(idx['sheets'])} sheets, {len(idx['views'])} views"
            f" in {idx['list_seconds']}s" + (" (failed)" if idx["errors"] else ""))
        self._notify("listed", slug=m.slug, rev=rev)
        # What was looked at lately, by name, comes first.
        now = time.time()
        for (slug, kind, name), t in list(self._recent.items()):
            if slug != m.slug or now - t > RECENT:
                continue
            for i, e in enumerate(idx["sheets"] if kind == "sheet" else idx["views"]):
                if e["name"] == name:
                    self.queue.put(m.slug, f"{kind}:{i + 1}", NEXT)
                    break

    @staticmethod
    def _prev_files(old: dict) -> dict | None:
        """The rendered pictures of a listing, by kind and name."""
        files, items = {}, old.get("items") or {}
        for kind in ("sheet", "view"):
            for i, e in enumerate(old.get(kind + "s") or []):
                f = (items.get(f"{kind}:{i + 1}") or {}).get("file")
                if f:
                    files.setdefault(f"{kind}:{e['name']}", f)
        f = (items.get("preview") or {}).get("file")
        if f:
            files["preview"] = f
        return {"rev": old["rev"], "files": files} if files else None

    def _view_cameras(self) -> list[dict]:
        """The saved views' cameras (read-only); none if they cannot be read."""
        try:
            reply = self._call("run_python", {"code": _SCENE_CAMERAS})
            if not reply.get("error"):
                for line in (reply.get("stdout") or "").splitlines():
                    if line.startswith(_MARK):
                        got = json.loads(line[len(_MARK):])
                        return [c for c in got if isinstance(c, dict)]
        except (RuntimeError, ValueError, AttributeError):
            pass
        return []

    def _layer_tree(self) -> dict:
        """The layers' folders (``{"folders": [{"name", "parent"}],
        "layers": {layer: folder}}``, read-only); empty if they cannot be
        read (an IngeTrazo without layer folders: the 3D view lists the
        layers flat)."""
        try:
            reply = self._call("run_python", {"code": _SCENE_LAYERS})
            if not reply.get("error"):
                for line in (reply.get("stdout") or "").splitlines():
                    if line.startswith(_MARK):
                        got = json.loads(line[len(_MARK):])
                        if (isinstance(got, dict) and isinstance(got.get("folders"), list)
                                and isinstance(got.get("layers"), dict)):
                            return {"folders": [
                                        {"name": str(f["name"]),
                                         "parent": str(f["parent"]) if f.get("parent") else None}
                                        for f in got["folders"]
                                        if isinstance(f, dict) and f.get("name")],
                                    "layers": {str(k): (str(v) if v else None)
                                               for k, v in got["layers"].items()}}
        except (RuntimeError, ValueError, AttributeError, KeyError, TypeError):
            pass
        return {}

    def _sheet_list(self, info: dict) -> list[dict]:
        """Every sheet in document order, with its folder path (a list of
        names, top first) and print flag when the app reports them."""
        names = list(info.get("sheets") or [])
        if not names:
            return []
        try:
            listed = self._call("list_sheets")
            rows = listed.get("sheets") if isinstance(listed, dict) else listed
            if isinstance(rows, list) and len(rows) == len(names):
                return [{"name": r.get("name", n), "folder": _path(r.get("folder")),
                         "printed": r.get("printed", r.get("print_in_all", True))}
                        for r, n in zip(rows, names)]
        except RuntimeError:
            pass
        return [{"name": n, "folder": [], "printed": True} for n in names]

    def _view_folders(self) -> dict[str, list[str]]:
        """Saved view name → its folder path (top first). ``list_scenes``
        names only the innermost folder, so the nesting is read from the
        document (read-only); without it, the innermost folder alone."""
        try:
            reply = self._call("run_python", {"code": _SCENE_FOLDERS})
            if not reply.get("error"):
                for line in (reply.get("stdout") or "").splitlines():
                    if line.startswith(_MARK):
                        got = json.loads(line[len(_MARK):])
                        return {str(k): [str(p) for p in v] for k, v in got.items()}
        except (RuntimeError, ValueError, AttributeError):
            pass
        try:
            listed = self._call("list_scenes")
            rows = listed.get("scenes") if isinstance(listed, dict) else listed
            return {r["name"]: _path(r.get("folder")) for r in rows or []
                    if isinstance(r, dict) and "name" in r}
        except (RuntimeError, KeyError, TypeError):
            return {}

    # ---- rendering ---------------------------------------------------------------
    def _render(self, m: Model, idx: dict, item: str) -> None:
        out = CACHE_DIR / m.slug / idx["rev"]
        out.mkdir(parents=True, exist_ok=True)
        target = out / item_file(item)
        state: dict = {"at": time.time()}
        t0 = time.monotonic()
        try:
            self._open_model(m, idx["rev"], clean=item == "glb")
            kind, _, n = item.partition(":")
            if kind == "glb":
                state.update(self._render_glb(target))
            elif kind == "pdf":
                self._dirty = True
                self._call("export_pdf", {"path": str(target), "format": "pdf",
                                          "sheets": list(range(1, len(idx["sheets"]) + 1))})
            elif kind == "sheet":
                state["warnings"] = self._render_sheet(out, int(n), SHEET_DPI, target)
            elif kind == "view":
                self._render_view(idx["views"][int(n) - 1]["name"], VIEW_W, VIEW_H, target)
            elif kind == "preview":
                if idx["sheets"]:
                    self._render_sheet(out, 1, PREVIEW_DPI, target)
                elif idx["views"]:
                    self._render_view(idx["views"][0]["name"], PREVIEW_W, PREVIEW_H, target)
                else:                       # no sheet, no saved view: the model
                    self._dirty = True
                    self._call("screenshot", {"path": str(target), "width": PREVIEW_W,
                                              "height": PREVIEW_H, "view": "iso", "fit": True})
            if not state.get("note"):
                if not target.is_file() or not target.stat().st_size:
                    raise RuntimeError("nothing was written")
                state["file"] = target.name
        except Exception as exc:
            state["error"] = str(exc)
            target.unlink(missing_ok=True)
        state["seconds"] = round(time.monotonic() - t0, 1)
        if not state.get("warnings"):
            state.pop("warnings", None)
        if not self._set_item(m.slug, idx["rev"], item, state):
            target.unlink(missing_ok=True)           # listed anew meanwhile
            return
        log(f"viewer: {m.name}: {item} in {state['seconds']}s"
            + (f" (worker {self._w.n})" if len(self.workers) > 1 else "")
            + (f": {state['error']}" if state.get("error") else ""))
        self._notify("done", slug=m.slug, rev=idx["rev"], item=item,
                     ok=not state.get("error"))

    def _render_sheet(self, out: Path, n: int, dpi: int, target: Path) -> list[str]:
        """Sheet ``n`` (1-based) as a PNG; the views on it that did not render."""
        self._dirty = True
        stem = out / f".tmp-{target.stem}.png"
        result = self._call("export_pdf", {"path": str(stem), "format": "png",
                                           "dpi": dpi, "sheets": [n]})
        files = [Path(f) for f in result.get("files") or []]
        if not files or not files[0].is_file():
            raise RuntimeError("not rendered")
        files[0].replace(target)
        for f in files[1:]:
            f.unlink(missing_ok=True)
        warnings = []
        for sheet, msgs in (result.get("views_not_rendered") or {}).items():
            for msg in msgs if isinstance(msgs, list) else [msgs]:
                warnings.append(f"{sheet}: {msg}")
        return warnings

    def _render_view(self, name: str, width: int, height: int, target: Path) -> None:
        self._dirty = True
        self._call("export_view", {"view": name, "path": str(target),
                                   "width": width, "height": height})

    def _render_glb(self, glb: Path) -> dict:
        """``model.glb`` for the 3D view. A file over ``VIEWER_GLB_MAX_MB``
        is deleted and noted, not counted as an error: it would not get any
        smaller by trying again.

        With an IngeTrazo that knows ``layers`` (ingelibre/ingetrazo#1684),
        the file carries the layers, hidden ones too, so the 3D view can
        switch them; an older one writes it without them."""
        try:
            self._call("export_file", {"path": str(glb), "layers": True})
        except RuntimeError as exc:
            if "layers" not in str(exc):
                raise
            self._call("export_file", {"path": str(glb)})
        size = glb.stat().st_size if glb.is_file() else 0
        if not size:
            raise RuntimeError("nothing was written")
        mb = size / 1_000_000
        if mb > GLB_MAX_MB:
            glb.unlink(missing_ok=True)
            log(f"viewer: {glb.parent.parent.name}: 3D model left out ({mb:.1f} MB)")
            return {"note": f"The 3D model is {mb:.1f} MB, more than the "
                            f"{GLB_MAX_MB:g} MB limit (VIEWER_GLB_MAX_MB)."}
        return {"mb": round(mb, 2)}
