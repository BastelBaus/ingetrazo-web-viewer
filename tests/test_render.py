# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests of the viewer's on-demand rendering, with a fake IngeTrazo
(no container needed):

    python -m unittest discover -s tests -p "test_*.py"
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mcp_http import folders  # noqa: E402
from viewer import render  # noqa: E402

MARK = render._MARK


class FakeApp:
    """Answers the bridge calls the renderer makes, and writes the files."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.delay = 0.0
        self.sheets = ["Plan", "Section"]
        self.views = ["Front", "Back", "Top"]

    def call(self, tool: str, args: dict | None = None) -> dict:
        args = args or {}
        self.calls.append((tool, args))
        if self.delay and tool in ("export_view", "export_pdf"):
            time.sleep(self.delay)
        if tool == "open_document":
            return {"ok": True, "result": {"sheets": self.sheets, "views": self.views}}
        if tool == "list_sheets":
            return {"ok": True, "result": {"sheets": [
                {"name": n, "folder": "A/B" if i else "", "print_in_all": True}
                for i, n in enumerate(self.sheets)]}}
        if tool == "run_python":
            if "_itz_viewer_layers" in args["code"]:
                out = {"folders": [{"name": "Building", "parent": None},
                                   {"name": "Walls", "parent": "Building"}],
                       "layers": {"Layer 0": None, "Outer": "Walls", "Roof": "Building"}}
            elif "cameras" in args["code"]:
                out = [{"name": v, "target": [0, 0, 0], "distance": 5, "yaw": 0,
                        "pitch": 0, "fov": 45, "perspective": True} for v in self.views]
            else:
                out = {v: ["Outside"] for v in self.views}
            import json
            return {"ok": True, "result": {"stdout": MARK + json.dumps(out)}}
        if tool == "export_pdf":
            path = Path(args["path"])
            if args.get("format") == "png":
                files = []
                for n in args["sheets"]:
                    f = path.with_name(f"{path.stem}-{n:02d}-x.png")
                    f.write_bytes(b"\x89PNG sheet")
                    files.append(str(f))
                return {"ok": True, "result": {"files": files}}
            path.write_bytes(b"%PDF")
            return {"ok": True, "result": {}}
        if tool in ("export_view", "export_file", "screenshot"):
            Path(args["path"]).write_bytes(b"glTF" if tool == "export_file" else b"\x89PNG")
            return {"ok": True, "result": {}}
        return {"ok": False, "error": f"unknown tool {tool}"}

    def tools(self) -> list[str]:
        out = [t if t != "export_pdf" else f"export_pdf:{a.get('format')}:{a.get('sheets')}"
               for t, a in self.calls]
        self.calls.clear()
        return out


class Base(unittest.TestCase):
    """A model folder with one model, a cache, a fake app."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name).resolve()
        self.data, cache = base / "data", base / "cache"
        (self.data / "p").mkdir(parents=True)
        self.model = self.data / "p" / "house.igz"
        self.model.write_bytes(b"one")
        os.utime(self.model, (time.time() - 60, time.time() - 60))
        self.saved = (folders.DATA_DIR, folders.FOLDERS, render.DATA_DIR,
                      render.CACHE_DIR, render.PRERENDER)
        folders.DATA_DIR = render.DATA_DIR = self.data
        folders.FOLDERS = folders.parse("p:rw", data_dir=self.data)
        render.CACHE_DIR = cache
        render.PRERENDER = "previews"
        self.app = FakeApp()
        self.r = render.Renderer(self.app)
        [self.slug] = [m["slug"] for m in self.r.models()]

    def tearDown(self):
        (folders.DATA_DIR, folders.FOLDERS, render.DATA_DIR,
         render.CACHE_DIR, render.PRERENDER) = self.saved
        self.tmp.cleanup()

    def drain(self) -> None:
        while not self.r.queue.empty():
            slug, item, prio = self.r.queue.pop(self.r._open[0] if self.r._open else None)
            self.r._task(slug, item, prio)


class RenderTest(Base):
    def test_background_renders_only_the_preview(self):
        self.r._scan()
        self.drain()
        self.assertEqual(self.app.tools(), ["open_document", "list_sheets", "run_python",
                                            "run_python", "run_python", "export_pdf:png:[1]"])
        idx = self.r.index(self.slug)
        self.assertTrue(self.r.fresh(self.slug))
        self.assertEqual([s["name"] for s in idx["sheets"]], ["Plan", "Section"])
        self.assertEqual(idx["sheets"][1]["folder"], ["A", "B"])
        self.assertEqual(idx["views"][0]["folder"], ["Outside"])
        self.assertEqual(len(idx["cameras"]), 3)
        self.assertEqual(idx["layer_tree"]["folders"][1], {"name": "Walls", "parent": "Building"})
        self.assertEqual(idx["layer_tree"]["layers"]["Outer"], "Walls")
        self.assertIsNone(idx["layer_tree"]["layers"]["Layer 0"])
        self.assertEqual(set(idx["items"]), {"preview"})
        f = render.CACHE_DIR / self.slug / idx["rev"] / idx["items"]["preview"]["file"]
        self.assertTrue(f.is_file())
        self.r._scan()                                 # nothing more to do
        self.assertTrue(self.r.queue.empty())

    def test_on_demand_and_priorities(self):
        self.r.request(self.slug, "view:3", render.NEXT)
        self.r.request(self.slug, "preview", render.PREVIEW)
        self.r.request(self.slug, "sheet:2", render.NOW)
        self.assertEqual(self.r.queue.pop(None)[1], "sheet:2")
        self.r.request(self.slug, "sheet:2", render.NOW)
        self.drain()
        idx = self.r.index(self.slug)
        self.assertEqual(set(idx["items"]), {"sheet:2", "view:3", "preview"})
        tools = self.app.tools()
        self.assertEqual(tools.count("open_document"), 1)  # listed once, kept open
        self.assertIn("export_pdf:png:[2]", tools)

    def test_glb_reopens_a_clean_document(self):
        self.r.request(self.slug, "view:1")
        self.drain()
        self.app.tools()
        self.r.request(self.slug, "glb")
        self.drain()
        self.assertEqual(self.app.tools(), ["open_document", "export_file"])
        self.assertTrue(self.r.state(self.r.index(self.slug), "glb").get("file"))

    def test_glb_asks_for_the_layers(self):
        self.r.request(self.slug, "glb")
        self.drain()
        exports = [a for t, a in self.app.calls if t == "export_file"]
        self.assertEqual(len(exports), 1)
        self.assertIs(exports[0].get("layers"), True)

    def test_glb_from_an_ingetrazo_without_layers(self):
        real = self.app.call

        def old_app(tool, args=None):
            if tool == "export_file" and (args or {}).get("layers"):
                self.app.calls.append((tool, args))
                return {"ok": False, "error": "_tool_export_file() got an "
                                              "unexpected keyword argument 'layers'"}
            return real(tool, args)
        self.app.call = old_app
        self.r.request(self.slug, "glb")
        self.drain()
        exports = [a for t, a in self.app.calls if t == "export_file"]
        self.assertEqual([a.get("layers") for a in exports], [True, None])
        self.assertTrue(self.r.state(self.r.index(self.slug), "glb").get("file"))

    def test_layer_tree_from_an_ingetrazo_without_folders(self):
        real = self.app.call

        def old_app(tool, args=None):
            if tool == "run_python" and "_itz_viewer_layers" in (args or {}).get("code", ""):
                return {"ok": True, "result": {"stdout": "", "error": "ImportError"}}
            return real(tool, args)
        self.app.call = old_app
        self.r.request(self.slug, "list")
        self.drain()
        self.assertEqual(self.r.index(self.slug)["layer_tree"], {})

    def test_a_changed_file_gets_a_new_rev_and_keeps_the_old_pictures(self):
        self.r.request(self.slug, "sheet:1")
        self.drain()
        old = self.r.index(self.slug)
        self.r.viewed(self.slug, "sheet:1", "Plan")
        self.model.write_bytes(b"two, longer")
        os.utime(self.model, (time.time() - 30, time.time() - 30))
        self.assertFalse(self.r.fresh(self.slug))
        self.r._scan()                                 # previews: lists again
        self.drain()
        idx = self.r.index(self.slug)
        self.assertNotEqual(idx["rev"], old["rev"])
        self.assertEqual(idx["prev"]["rev"], old["rev"])
        self.assertIn("sheet:Plan", idx["prev"]["files"])
        self.assertTrue((render.CACHE_DIR / self.slug / old["rev"]).is_dir())
        # The sheet looked at lately was rendered again by itself.
        self.assertIn("sheet:1", idx["items"])

    def test_settling_file_waits(self):
        self.model.write_bytes(b"being written")
        self.r.request(self.slug, "list")
        slug, item, prio = self.r.queue.pop(None)
        self.r._task(slug, item, prio)
        self.assertEqual(self.app.tools(), [])
        self.assertEqual(self.r.queue.pending(self.slug), {"list"})

    def test_prerender_all(self):
        render.PRERENDER = "all"
        self.r._scan()
        self.drain()
        idx = self.r.index(self.slug)
        self.assertEqual(set(idx["items"]), {"glb", "preview", "sheet:1", "sheet:2",
                                             "view:1", "view:2", "view:3", "pdf"})
        self.r._scan()
        self.assertTrue(self.r.queue.empty())

    def test_prerender_all_order(self):
        """Every model's preview first, then views, sheets, 3D, and the PDF
        last of all."""
        other = self.data / "p" / "barn.igz"
        other.write_bytes(b"barn")
        os.utime(other, (time.time() - 60, time.time() - 60))
        self.r._refresh_models()
        render.PRERENDER = "all"
        self.r._scan()
        order = []
        while not self.r.queue.empty():
            slug, item, prio = self.r.queue.pop(self.r._open[0] if self.r._open else None)
            self.r._task(slug, item, prio)
            if item not in ("all", "list"):
                order.append((slug, item))
        items = [i for _, i in order]
        self.assertEqual(items[:2], ["preview", "preview"])          # both models
        self.assertEqual(len({s for s, _ in order[:2]}), 2)
        per_model = [i for s, i in order if s == self.slug]
        self.assertEqual(per_model, ["preview", "view:1", "view:2", "view:3",
                                     "sheet:1", "sheet:2", "glb", "pdf"])
        self.assertEqual(items[-2:], ["pdf", "pdf"])                  # PDFs after all else

    def test_two_workers_render_side_by_side(self):
        apps = [FakeApp(), FakeApp()]
        for a in apps:
            a.delay = 0.05
        r = render.Renderer(apps)
        r.request(self.slug, "list")
        for i in range(1, 4):
            r.request(self.slug, f"view:{i}")
        for i in range(1, 3):
            r.request(self.slug, f"sheet:{i}")
        for w in r.workers:
            threading.Thread(target=r._work, args=(w,), daemon=True).start()
        deadline = time.time() + 10
        while (not r.queue.empty() or r.rendering) and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.1)
        idx = r.index(self.slug)
        self.assertEqual(set(idx["items"]), {"view:1", "view:2", "view:3",
                                             "sheet:1", "sheet:2"})   # none lost
        self.assertTrue(all(st.get("file") for st in idx["items"].values()))
        self.assertTrue(all(a.calls for a in apps))                   # both worked
        listings = sum(1 for a in apps for t, _ in a.calls if t == "list_sheets")
        self.assertEqual(listings, 1)                                 # listed once

    def test_removed_model_drops_its_cache(self):
        self.r._scan()
        self.drain()
        self.model.unlink()
        self.r._scan()
        self.assertFalse((render.CACHE_DIR / self.slug).exists())
        kinds = [e["kind"] for e in self.r.events_since(0)]
        self.assertIn("removed", kinds)
        self.assertIn("models", kinds)


class StatusTest(Base):
    """The admin's render list (``Renderer.status``, ``/admin/renders``)."""

    def test_status_of_every_view_sheet_3d_and_pdf(self):
        [m] = self.r.status()
        self.assertFalse(m["listed"])
        self.assertEqual(m["items"], [])
        self.r.request(self.slug, "view:2")
        self.drain()
        [m] = self.r.status()
        st = {e["item"]: e["status"] for e in m["items"]}
        self.assertEqual(list(st), ["view:1", "view:2", "view:3", "sheet:1", "sheet:2",
                                    "glb", "pdf"])
        self.assertEqual(st["view:2"], "rendered")
        self.assertEqual(st["pdf"], "missing")
        names = {e["item"]: (e["name"], e["folder"]) for e in m["items"]}
        self.assertEqual(names["sheet:2"], ("Section", ["A", "B"]))
        self.assertEqual(names["glb"], ("3D model", []))
        self.r.request(self.slug, "pdf", render.LAST)
        self.assertEqual({e["item"]: e["status"] for e in self.r.status()[0]["items"]}["pdf"],
                         "queued")
        self.r.workers[0].rendering = (self.slug, "glb")
        self.assertEqual({e["item"]: e["status"] for e in self.r.status()[0]["items"]}["glb"],
                         "rendering")
        self.r.workers[0].rendering = None
        self.model.write_bytes(b"two, changed")              # the model changed
        os.utime(self.model, (time.time() - 60, time.time() - 60))
        st = {e["item"]: e["status"] for e in self.r.status()[0]["items"]}
        self.assertEqual(st["view:2"], "outdated")

    def test_failed_render_shows_the_error(self):
        self.r.request(self.slug, "list")
        self.drain()
        rev = self.r.index(self.slug)["rev"]
        self.r._set_item(self.slug, rev, "glb", {"error": "too big", "at": time.time()})
        e = {e["item"]: e for e in self.r.status()[0]["items"]}["glb"]
        self.assertEqual((e["status"], e["detail"]), ("failed", "too big"))

    def test_admin_page(self):
        from types import SimpleNamespace

        from viewer import admin
        self.r.request(self.slug, "view:1")
        self.drain()
        auth = SimpleNamespace(sessions=SimpleNamespace(csrf=lambda name: "tok"), mode="local")
        user = SimpleNamespace(name="admin", admin=True)
        from viewer import server
        saved = getattr(server, "auth", None)
        server.auth = SimpleNamespace(mode="none")       # the top bar without an account
        try:
            html = admin.renders_page(auth, user, self.r.status(), title="T").decode()
        finally:
            server.auth = saved
        self.assertIn(f'href="/m/{self.slug}?view=1">Front</a>', html)
        self.assertIn(f'href="/m/{self.slug}?3d=1">3D model</a>', html)
        self.assertIn(f'href="/m/{self.slug}?pdf=1">PDF</a>', html)
        self.assertIn('class="st rendered">rendered', html)
        self.assertIn("1 / 7 rendered", html)
        self.assertIn('value="render-all"', html)


class PagesTest(Base):
    """The viewer's pages ask for what they show, and wait for it."""

    def setUp(self):
        super().setUp()
        from types import SimpleNamespace

        from viewer import server
        self.server = server
        self.saved_server = getattr(server, "renderer", None), getattr(server, "auth", None)
        server.renderer = self.r
        server.auth = SimpleNamespace(mode="none")

    def tearDown(self):
        self.server.renderer, self.server.auth = self.saved_server
        super().tearDown()

    def test_overview_asks_for_previews(self):
        html = self.server.overview().decode()
        self.assertIn("preview…", html)
        self.assertEqual(self.r.queue.pending(self.slug), {"preview"})
        self.drain()
        html = self.server.overview().decode()
        self.assertIn('<img src="/files/', html)
        self.assertIn("2 sheets · 3 views", html)

    def test_model_page_renders_what_is_on_screen(self):
        html = self.server.model_page(self.slug).decode()
        self.assertIn('data-wait="list"', html)                 # not listed yet
        self.drain()
        self.app.tools()
        html = self.server.model_page(self.slug, query={"view": ["2"]}).decode()
        self.assertIn('data-wait="view:2"', html)
        self.assertIn("Rendering…", html)
        self.assertEqual(self.r.queue.pending(self.slug), {"view:2", "view:1", "sheet:2"})  # Back: Front next, last sheet before
        self.assertEqual(self.r.queue.pop(None)[1], "view:2")     # NOW before NEXT
        self.r._task(self.slug, "view:2", render.NOW)
        html = self.server.model_page(self.slug, query={"view": ["2"]}).decode()
        self.assertIn('data-wait=""', html)
        self.assertIn('<img src="/files/', html)

    def test_pdf_on_request(self):
        self.r.request(self.slug, "list")
        self.drain()
        page, url = self.server.pdf_page(self.slug)
        self.assertIn('data-wait="pdf"', page.decode())
        self.drain()
        page, url = self.server.pdf_page(self.slug)
        self.assertIsNone(page)
        self.assertTrue(url.endswith("/sheets.pdf"))

    def test_3d_on_request(self):
        self.r.request(self.slug, "list")
        self.drain()
        html = self.server.model_page(self.slug, query={"3d": ["1"]}).decode()
        self.assertIn('data-wait="glb"', html)
        self.drain()
        html = self.server.model_page(self.slug, query={"3d": ["1"]}).decode()
        self.assertIn('id="stage"', html)
        self.assertIn("model.glb", html)
        self.assertIn('data-layer-tree="{&quot;folders&quot;: [{&quot;name&quot;: &quot;Building&quot;', html)

    def test_shares_hide_models(self):
        from types import SimpleNamespace

        from mcp_http.users import Users
        users = Users(Path(self.tmp.name) / "users.db")
        users.create("anna", "anna-pass")
        self.server.auth = SimpleNamespace(mode="local", users=users, settings=lambda u: {},
                                           sessions=SimpleNamespace(csrf=lambda n: "t"))
        anna = SimpleNamespace(name="anna", admin=False)
        self.assertIn("house.igz", self.server.overview(anna).decode())   # default: read all
        users.set_shares("anna", [{"path": "p/other", "access": "r"}])
        html = self.server.overview(anna).decode()
        self.assertNotIn("house.igz", html)
        self.assertIsNone(self.server.model_page(self.slug, anna))
        users.set_shares("anna", [{"path": "p", "access": "r"}])
        self.assertIsNotNone(self.server.model_page(self.slug, anna))

    def test_dropdowns_view_3d_sheet(self):
        self.r.request(self.slug, "list")
        self.drain()
        html = self.server.model_page(self.slug).decode()
        kinds = [html.index(f'data-kind="{k}"') for k in ("view", "3d", "sheet")]
        self.assertEqual(kinds, sorted(kinds))                 # View, 3D, Sheet
        self.assertNotIn('id="cam"', html)                     # no picker below
        self.assertIn('href="?3d=1&amp;cam=2"', html)          # a saved view's camera
        self.assertIn('data-cam="2"', html)
        # The cameras sit in their saved views' folders.
        self.assertIn('data-p="[&quot;Outside&quot;]"', html)
        self.assertIn('class="dd-mode"', html)                 # list / tree switch
        self.assertIn('data-nav="tree"', html)                 # tree by default

    def test_3d_dropdown_marks_the_camera(self):
        self.r.request(self.slug, "list")
        self.drain()
        html = self.server.model_page(self.slug, query={"3d": ["1"], "cam": ["3"]}).decode()
        self.assertIn('href="?3d=1&amp;cam=3" class="on"', html)
        html = self.server.model_page(self.slug, query={"3d": ["1"], "cam": ["99"]}).decode()
        self.assertIn('href="?3d=1" class="on"', html)       # unknown: the whole model

    def test_views_alphabetical(self):
        self.app.views = ["view 10", "Zimmer", "View 2", "attic"]
        self.r.request(self.slug, "list")
        self.drain()
        html = self.server.model_page(self.slug, query={"view": ["1"]}).decode()
        panel = html[html.index('data-kind="view"'):html.index('data-kind="3d"')]
        order = [panel.index(f'>{n}</a>') for n in ("attic", "View 2", "view 10", "Zimmer")]
        self.assertEqual(order, sorted(order))
        # Links keep the document's numbers; Prev/Next walk the sorted order.
        self.assertIn('href="?view=4"', panel)
        self.assertIn('id="next" href="?view=2"', html)        # view 10 → Zimmer
        self.assertIn('id="prev" href="?view=3"', html)        # view 10 ← View 2

    def test_natural_key(self):
        names = ["b", "A10", "a2", "B1"]
        self.assertEqual(sorted(names, key=self.server._natural), ["a2", "A10", "b", "B1"])

    def test_dropdown_rows_know_their_folder(self):
        html = self.server._dropdown("Sheet", [("?sheet=1", "Plan", []),
                                               ("?sheet=2", "Cut", ["A", "Ä B"])], "?sheet=2")
        self.assertIn('data-in="[&quot;A&quot;,&quot;Ä B&quot;]"', html)
        self.assertIn('data-p="[&quot;A&quot;]"', html)
        self.assertIn('data-p="[&quot;A&quot;,&quot;Ä B&quot;]"', html)
        flat = self.server._dropdown("Sheet", [("?sheet=1", "Plan", [])])
        self.assertNotIn("dd-mode", flat)                       # no folders: no switch


if __name__ == "__main__":
    unittest.main()
