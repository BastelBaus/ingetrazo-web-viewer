# SPDX-License-Identifier: AGPL-3.0-or-later
"""Smoke test of the viewer: smoke_viewer.py <base-url> <user> <password>

Runs after smoke_mcp.py, which saved smoke-saved.igz into the shared data
folder: the viewer must pick that file up by itself (live update)."""
from __future__ import annotations

import base64
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE, USER, PASSWORD = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect)


def get(path, headers=None, data=None, timeout=60):
    req = urllib.request.Request(BASE + path, data, headers or {})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


BASIC = {"Authorization": "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()}


def check(label, fn):
    t0 = time.monotonic()
    fn()
    print(f"  ok  {label} ({time.monotonic() - t0:.1f}s)")


def wait_for(pred, what, timeout=240):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            got = pred()
            if got:
                return got
        except OSError:
            pass
        time.sleep(2)
    raise SystemExit(f"viewer: timed out waiting for {what}")


def model_page(name, query=""):
    """The model's page once what it shows is rendered (the viewer renders
    it when the page asks for it)."""
    status, _, body = get("/", BASIC)
    if status != 200:
        return None
    html = body.decode()
    m = re.search(r'href="(/m/[^"]+)"><div class="thumb">(?:(?!</a>).)*class="name">'
                  + re.escape(name) + "<", html, re.S)
    if not m:
        return None
    status, _, page = get(m.group(1) + query, BASIC)
    page = page.decode()
    return page if status == 200 and 'data-wait=""' in page else None


def main():
    print("== viewer")
    check("healthz", lambda: wait_for(
        lambda: get("/healthz")[0] == 200, "healthz"))

    def auth():
        status, headers, _ = get("/", {"Accept": "text/html"})
        assert status == 303 and headers["Location"].startswith("/login"), status
        status, _, _ = get("/")
        assert status == 401, status
        status, _, _ = get("/login", data=urllib.parse.urlencode(
            {"user": USER, "password": "wrong", "next": "/"}).encode())
        assert status == 401, status
        status, headers, _ = get("/login", data=urllib.parse.urlencode(
            {"user": USER, "password": PASSWORD, "next": "//evil.example"}).encode())
        assert status == 303 and headers["Location"] == "/", (status, headers.get("Location"))
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, _, _ = get("/", {"Cookie": cookie})
        assert status == 200, status
    check("login page, cookie, basic auth, safe redirect", auth)

    def preview():
        def thumb():
            status, _, body = get("/", BASIC)
            m = re.search(r'<img src="(/files/[^"]+preview[^"]+\.png)"', body.decode())
            return m and m.group(1)
        png = wait_for(thumb, "the preview of arco.igz (VIEWER_PRERENDER=previews)")
        status, headers, body = get(png, BASIC)
        assert status == 200 and headers["Content-Type"] == "image/png" \
            and body.startswith(b"\x89PNG"), status
    check("overview: a preview per model", preview)

    def rendered():
        page = wait_for(lambda: model_page("arco.igz"), "arco.igz's first sheet to render")
        png = re.search(r'<img src="(/files/[^"]+\.png)"', page).group(1)
        status, headers, body = get(png, BASIC)
        assert status == 200 and headers["Content-Type"] == "image/png" \
            and body.startswith(b"\x89PNG"), status
        slug = re.search(r'data-slug="([^"]+)"', page).group(1)

        def pdf():
            status, headers, _ = get(f"/m/{slug}?pdf=1", BASIC)
            return headers.get("Location") if status == 303 else None
        url = wait_for(pdf, "the PDF")
        status, headers, body = get(url, BASIC)
        assert status == 200 and body.startswith(b"%PDF"), status
    check("arco.igz: a sheet rendered on demand, the PDF on request", rendered)

    def one_at_a_time():
        page = model_page("arco.igz")
        assert page.count("<figure") == 1, page.count("<figure")
        links = re.findall(r'<a href="\?(sheet|view)=(\d+)"', page)
        assert links, "no sheet/view links in the top bar"
        slug = re.search(r'data-slug="([^"]+)"', page).group(1)
        for kind, n in links:
            status, _, body = get(f"/m/{slug}?{kind}={n}", BASIC)
            body = body.decode()
            assert status == 200 and body.count("<figure") == 1, (kind, n, status)
            assert f'href="?{kind}={n}" class="on"' in body, (kind, n)
            wait_for(lambda: model_page("arco.igz", f"?{kind}={n}"),
                     f"{kind} {n} to render")
    check("model page shows one sheet or view at a time, rendered on demand", one_at_a_time)

    def three_d():
        page = model_page("arco.igz")
        assert 'href="?3d=1"' in page, "no 3D button"
        slug = re.search(r'data-slug="([^"]+)"', page).group(1)
        body = wait_for(lambda: model_page("arco.igz", "?3d=1"), "the 3D model")
        assert 'id="stage"' in body
        glb = re.search(r'data-glb="([^"]+)"', body).group(1)
        status, headers, data = get(glb, BASIC)
        assert status == 200 and headers["Content-Type"] == "model/gltf-binary" \
            and data[:4] == b"glTF", (status, headers.get("Content-Type"), data[:4])
        for lib in ("three.module.min.js", "addons/loaders/GLTFLoader.js",
                    "addons/controls/OrbitControls.js", "addons/utils/BufferGeometryUtils.js"):
            status, headers, data = get("/static/three/" + lib, BASIC)
            assert status == 200 and headers["Content-Type"].startswith("text/javascript") \
                and data, (lib, status)
        assert get("/static/three/three.module.min.js")[0] == 401, "library without login"
        assert get("/static/three/../render.py", BASIC)[0] == 404
    check("3D view: page, GLB and three.js", three_d)

    check("picks up the model saved over MCP", lambda: wait_for(
        lambda: model_page("smoke-saved.igz"), "smoke-saved.igz to render"))
    assert get("/files/../etc/passwd", BASIC)[0] == 404
    assert get("/files/x/../passwd", BASIC)[0] == 404

    def admin_pages():
        # The real process (python -m viewer.server): admin.py imports
        # viewer.server, which must be the copy main() set up.
        for path in ("/admin", "/account", "/admin/log"):
            status, _, body = get(path, BASIC)
            assert status == 200, (path, status, body[:200])
    check("admin and account pages", admin_pages)
    print("== viewer: ok")


if __name__ == "__main__":
    main()
