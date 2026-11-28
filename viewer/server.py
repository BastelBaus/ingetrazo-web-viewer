# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only live viewer: the sheets and saved views of the models in the
model folders, in the browser, rendered when someone looks at them
(render.py) and refreshed when a model file changes.

Routes: ``/`` overview (folder by folder, a preview per model), ``/m/<slug>``
one model, one sheet or view at a time (``?sheet=N`` / ``?view=N``,
1-based), the model in 3D (``?3d=1``) or its sheets as PDF (``?pdf=1``),
``/files/<slug>/<rev>/<f>`` rendered images, PDF and GLB, ``/static/<f>``
the 3D view's script library (three.js), ``/events`` server-sent events
(a listing or render started or finished),
``/admin`` the user list (admins), ``/admin/renders`` the render status
(admins), ``/account`` one's own account,
``/avatar/<user>.svg`` a user's avatar,
``/version`` the running build (JSON),
``/healthz`` (always open). Who may see the rest: ``VIEWER_AUTH_MODE``
(see auth.py) — ``local`` (``/login``, ``/logout``, Basic auth for
scripts), ``none``, ``oidc`` (``/auth/login``, ``/auth/callback``) or
``proxy``.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import sys
import threading
import time
from html import escape
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from mcp_http import folders, shares
from mcp_http.common import log
from mcp_http.users import UserError

from . import admin, audit, avatar, site, version
from mcp_http.remote import RemoteApp, engine_urls
from .auth import Auth, User
from .render import (BACKGROUND, CACHE_DIR, GLB_MAX_MB, NEXT, NOW, POLL, PRERENDER, PREVIEW,
                     WITH_PDF, Renderer)
from .view3d import THREE_DIR, view3d

renderer: Renderer
auth: Auth
#: How the View / 3D / Sheet dropdowns show folders by default: "tree"
#: (one level at a time, the default) or "list" (every level at once). Each
#: browser can switch in the dropdown.
NAV_MODE = "list" if os.environ.get("VIEWER_NAV_MODE", "").strip().lower() == "list" else "tree"
_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")

CSS = """
:root{--bg:#f6f6f4;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--line:#e2e1dc;
--accent:#2f6fb2;--ok:#2e8b57;--warn:#b7791f;--sheet:#fff;--shadow:0 1px 3px rgba(0,0,0,.08)}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#20201e;--fg:#ecebe6;
--muted:#9b9a94;--line:#33322f;--accent:#6aa5e6;--sheet:#fafaf8;--shadow:none}}
*{box-sizing:border-box}html{scroll-padding-top:64px}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
header{position:sticky;top:0;z-index:5;display:flex;gap:12px;align-items:center;flex-wrap:wrap;
padding:10px 16px;background:color-mix(in srgb,var(--bg) 88%,transparent);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
header h1{font-size:17px;margin:0;font-weight:600;overflow-wrap:anywhere}
header .meta{color:var(--muted);font-size:13px}
.spacer{flex:1}
.live{display:inline-flex;align-items:center;gap:6px;font-size:13px;color:var(--muted)}
.live i{width:8px;height:8px;border-radius:50%;background:var(--muted);display:inline-block}
.live.on i{background:var(--ok)}.live.busy i{background:var(--warn);animation:pulse 1s infinite}
@keyframes pulse{50%{opacity:.3}}
.btn{border:1px solid var(--line);background:var(--card);padding:5px 10px;border-radius:6px;font-size:13px;color:var(--fg)}
main{padding:16px;max-width:1500px;margin:0 auto}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;box-shadow:var(--shadow);color:var(--fg)}
.card:hover{text-decoration:none;border-color:var(--accent)}
.card .thumb{aspect-ratio:16/10;background:var(--sheet);display:flex;align-items:center;justify-content:center;border-bottom:1px solid var(--line)}
.card .thumb img{max-width:100%;max-height:100%;object-fit:contain}
.card .body{padding:10px 12px}.card .name{font-weight:600;overflow-wrap:anywhere}
.card .sub{color:var(--muted);font-size:13px}
header.bar{padding:6px 12px;gap:8px;flex-wrap:nowrap}
header.bar h1{font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:3em;max-width:22vw}
.navs{display:flex;gap:8px;min-width:0;flex:0 1 auto}
.dd{position:relative;min-width:0}
.dd>summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:6px;max-width:38vw;
border:1px solid var(--line);background:var(--card);padding:4px 8px;border-radius:6px;font-size:13px;white-space:nowrap;overflow:hidden}
.dd>summary::-webkit-details-marker{display:none}
.dd>summary::after{content:"";border:4px solid transparent;border-top-color:var(--muted);margin:4px 0 0 2px}
.dd[open]>summary,.dd>summary:hover{border-color:var(--accent)}
.dd .k{flex:none;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.dd .cur{flex:0 1 auto;overflow:hidden;text-overflow:ellipsis;min-width:0}.dd>summary::after{flex:none}.dd .cur .p{color:var(--muted)}
.dd-panel{position:absolute;top:calc(100% + 6px);left:0;z-index:10;width:min(380px,calc(100vw - 24px));
max-height:min(70vh,560px);display:flex;flex-direction:column;background:var(--card);border:1px solid var(--line);
border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.18)}
.dd-tools{display:flex;gap:6px;align-items:center;margin:8px}.dd-tools:empty{display:none}
.dd-mode{flex:none;margin-left:auto;border:1px solid var(--line);background:var(--card);color:var(--fg);
padding:4px 8px;border-radius:6px;font:inherit;font-size:12px;cursor:pointer}
.dd-mode:hover{border-color:var(--accent)}
.dd-up{display:block;padding:5px 12px;font-size:13px;color:var(--accent);cursor:pointer;border-bottom:1px solid var(--line);
white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.dd-up[hidden]{display:none}
.dd-filter{flex:1;min-width:0;margin:0;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font:inherit;font-size:14px}
.dd-list{overflow:auto;padding:4px 0 8px;font-size:14px}
.dd-list a,.dd-list .f{display:block;padding:3px 12px 3px calc(12px + var(--d,0) * 14px);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dd-list a{color:var(--fg)}.dd-list a:hover{background:var(--bg);text-decoration:none}
.dd-list a.on{background:color-mix(in srgb,var(--accent) 14%,transparent);font-weight:600}
.dd-list .f{color:var(--muted);font-size:12px;padding-top:7px}.dd-list .f::before{content:"▸ "}
.dd-list .none{font-style:italic}.dd-list .none::before{content:""}
.dd-empty{color:var(--muted);padding:6px 12px;font-size:13px}
.dd-list>[hidden]{display:none}
.dd-list.tree>a,.dd-list.tree>.f{padding-left:12px}
.dd-list.tree>.f{cursor:pointer;color:var(--fg);font-size:14px;padding-top:3px}
.dd-list.tree>.f::before{content:""}.dd-list.tree>.f::after{content:" ›";color:var(--muted)}
.dd-list.tree>.f:hover{background:var(--bg)}
section h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:8px 0 12px}
figure{margin:0 0 28px;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden;box-shadow:var(--shadow)}
figure a.img{display:block;background:var(--sheet)}
figure img{display:block;width:100%;height:auto}
figcaption{display:flex;gap:10px;align-items:baseline;padding:8px 12px;font-size:14px;border-top:1px solid var(--line)}
figcaption .muted,.muted{color:var(--muted);font-size:13px}
footer.ver{color:var(--muted);font-size:12px;text-align:center;padding:4px 16px 12px}
.step{display:flex;gap:4px;flex:none}.step .btn{padding:3px 10px;font-size:15px;line-height:1.2}
.step .btn:hover{text-decoration:none;border-color:var(--accent)}
figure.one{margin:0}
/* The one sheet or view fits the window below the top bar (~48px) and its caption (~40px). */
figure.one img{width:auto;max-width:100%;max-height:calc(100vh - 48px - 40px - 32px);margin:0 auto;object-fit:contain}
.errors{background:color-mix(in srgb,var(--warn) 12%,var(--card));border:1px solid var(--warn);border-radius:8px;padding:8px 12px;margin-bottom:16px;font-size:13px}
.empty{color:var(--muted);padding:40px 0;text-align:center}
@media (max-width:820px){figure.one img{max-height:none}
header.bar{flex-wrap:wrap}header.bar h1{max-width:none;flex:1}header.bar .meta{display:none}
.navs{order:9;flex:1 1 100%}.navs .dd{position:static;flex:1 1 0}.dd>summary{max-width:none}
.dd .cur{flex:1 1 auto}
.dd-panel{left:12px;width:auto;right:12px}}
.btn.on{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 14%,var(--card));font-weight:600}
a.btn:hover{text-decoration:none;border-color:var(--accent)}
.who{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:14em;display:inline-flex;align-items:center;gap:6px}
img.avatar{border-radius:50%;flex:none;vertical-align:middle}
@media (max-width:820px){.who{display:none}}
.pending{display:flex;align-items:center;justify-content:center;min-height:min(60vh,520px);background:var(--sheet);color:#6b6b66}
.pending span::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;
background:var(--warn);animation:pulse 1s infinite}
section.folder{margin-bottom:28px}
.tag{font-size:11px;letter-spacing:.04em;border:1px solid var(--line);border-radius:4px;padding:1px 5px;vertical-align:middle}
"""

JS = """
// Saves one of the user's settings (/account/settings); the page keeps
// working when that fails.
window.saveSetting = function(key, value){
  const csrf = document.body.dataset.csrf;
  if (!csrf) return Promise.resolve(false);
  const body = new URLSearchParams({csrf: csrf, [key]: String(value)});
  return fetch('/account/settings', {method: 'POST', body: body, credentials: 'same-origin'})
    .then(r => r.ok).catch(() => false);
};
(function(){
  const slug = document.body.dataset.slug || null;
  // What this page waits for: a listing ("list"), "preview", "sheet:N", …
  const wait = (document.body.dataset.wait || '').split(' ').filter(Boolean);
  const dot = document.getElementById('live');
  const key = 'scroll:' + location.pathname;
  try { const y = sessionStorage.getItem(key); if (y !== null) { sessionStorage.removeItem(key);
        window.scrollTo(0, parseInt(y, 10)); } } catch (e) {}
  function set(state, text){ if (!dot) return; dot.className = 'live ' + state;
                             dot.querySelector('span').textContent = text; }
  function reload(){
    try { sessionStorage.setItem(key, String(window.scrollY)); } catch (e) {}
    location.reload();
  }
  function connect(){
    const es = new EventSource('/events');
    es.onopen = () => set('on', 'live');
    es.onerror = () => set('', 'reconnecting…');
    es.onmessage = (m) => {
      let ev; try { ev = JSON.parse(m.data); } catch (e) { return; }
      if (ev.kind === 'idle') { set('on', 'live'); return; }
      if (ev.kind === 'rendering') {
        if (!slug || ev.slug === slug) set('busy', 'rendering…');
        return;
      }
      if (slug) {
        // A model page: its model changed, or what it waits for is done.
        if (ev.slug === slug && (ev.kind === 'listed' || ev.kind === 'removed'
            || (ev.kind === 'done' && wait.includes(ev.item)))) reload();
      } else if (ev.kind === 'models' || ev.kind === 'removed' || ev.kind === 'listed'
                 || (ev.kind === 'done' && wait.includes(ev.item))) {
        reload();                    // the overview
      }
    };
  }
  if (window.EventSource) connect();

  // ---- the View / 3D / Sheet dropdowns of the top bar ----
  const header = document.querySelector('header');
  const dds = Array.from(document.querySelectorAll('details.dd'));
  if (!dds.length) return;
  function pad(){ document.documentElement.style.scrollPaddingTop = (header.offsetHeight + 8) + 'px'; }
  pad(); window.addEventListener('resize', pad);
  function closeAll(except){ dds.forEach(d => { if (d !== except) d.open = false; }); }
  // "list": every level at once; "tree": one level, folders to step into.
  // The server's default (data-nav), or what this browser chose.
  // A user with an account keeps the choice in their settings (data-nav,
  // saved below); without one, this browser keeps it.
  const csrf = document.body.dataset.csrf || '';
  let mode = document.body.dataset.nav === 'tree' ? 'tree' : 'list';
  if (!csrf) try { const m = localStorage.getItem('navmode'); if (m === 'tree' || m === 'list') mode = m; } catch (e) {}
  const SEP = ' › ';
  function setup(dd){
    const filter = dd.querySelector('.dd-filter');
    const list = dd.querySelector('.dd-list');
    const up = dd.querySelector('.dd-up');
    const btn = dd.querySelector('.dd-mode');
    const rows = Array.from(list.children);
    const folders = rows.some(r => r.dataset.p);
    let at = [];                              // the tree's current folder
    function flat(q){
      list.classList.remove('tree'); up.hidden = true;
      let any = false;
      rows.forEach(r => { if (r.tagName === 'A') {
        const hit = !q || (r.dataset.folder + ' ' + r.textContent).toLowerCase().includes(q);
        r.hidden = !hit; any = any || hit; } });
      // A folder heading stays while something below it (deeper) is shown.
      rows.forEach((r, i) => { if (r.tagName === 'A') return;
        const d = +r.style.getPropertyValue('--d') || 0; let keep = false;
        for (let j = i + 1; j < rows.length; j++) {
          const rj = rows[j], dj = +rj.style.getPropertyValue('--d') || 0;
          if (rj.tagName !== 'A' && dj <= d) break;
          if (rj.tagName === 'A' && !rj.hidden) { keep = true; break; } }
        r.hidden = !keep; });
      dd.querySelector('.dd-empty').hidden = any;
    }
    function tree(path){
      at = path; const key = JSON.stringify(path);
      list.classList.add('tree');
      rows.forEach(r => { r.hidden = r.classList.contains('none') || r.dataset.in !== key; });
      up.hidden = !path.length;
      up.textContent = '‹ ' + path.join(SEP);
      dd.querySelector('.dd-empty').hidden = true;
    }
    function show(){
      const q = filter ? filter.value.trim().toLowerCase() : '';
      if (btn) { btn.textContent = mode === 'tree' ? 'List' : 'Tree';
                 btn.setAttribute('aria-pressed', String(mode === 'tree')); }
      if (mode === 'tree' && folders && !q) tree(at); else flat(q);
    }
    dd._show = show;
    function start(){
      // The tree opens at the folder of what is on screen.
      const on = dd.querySelector('a.on');
      try { at = on ? JSON.parse(on.dataset.in || '[]') : []; } catch (e) { at = []; }
    }
    list.addEventListener('click', (e) => {
      const f = e.target.closest('.f');
      if (!f || !f.dataset.p || !list.classList.contains('tree')) return;
      tree(JSON.parse(f.dataset.p));
    });
    up.addEventListener('click', () => tree(at.slice(0, -1)));
    if (btn) btn.addEventListener('click', (e) => {
      e.preventDefault();
      mode = mode === 'tree' ? 'list' : 'tree';
      if (csrf) window.saveSetting('nav_mode', mode);
      else try { localStorage.setItem('navmode', mode); } catch (err) {}
      start(); dds.forEach(d => d._show && d._show());
    });
    dd.addEventListener('toggle', () => {
      if (!dd.open) return;
      closeAll(dd);
      start(); show();
      const on = dd.querySelector('a.on');
      if (on && !on.hidden) on.scrollIntoView({block: 'nearest'});
      if (filter && matchMedia('(pointer:fine)').matches) filter.focus();
    });
    if (filter) filter.addEventListener('input', show);
    start(); show();
  }
  dds.forEach(setup);
  document.addEventListener('click', (e) => { if (!e.target.closest('details.dd')) closeAll(null); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { closeAll(null); return; }
    // ← / → step to the previous / next sheet or view, unless typing.
    if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey || dds.some(d => d.open)) return;
    if (e.target.closest && e.target.closest('input,textarea,select,[contenteditable]')) return;
    const a = document.getElementById(e.key === 'ArrowLeft' ? 'prev' : e.key === 'ArrowRight' ? 'next' : '');
    if (a) { e.preventDefault(); location.href = a.href; }
  });
})();
"""


def _account(user: User | None) -> str:
    """The top bar's right end: who is logged in (their own page), the
    admin panel for admins, and the way out."""
    if user is None or auth.mode == "none":
        return ""
    role = " (admin)" if user.admin else ""
    who = (f'<a class="muted who" href="/account" title="{escape(user.name + role)}">'
           f'{avatar_img(user.name, 22)}{escape(user.name)}</a>')
    admin = ('<a class="btn" href="/admin" title="Users and renders">Admin</a>'
             if user.admin else "")
    out = ('<a class="btn" href="/logout">Log out</a>'
           if auth.mode != "proxy" or auth.proxy.logout_url else "")
    return who + admin + out


def _settings(user: User | None) -> str:
    """The body's data-* attributes with the user's settings, and the token
    the page's script saves a changed one with (users with an account)."""
    conf = (auth.settings(user) if hasattr(auth, "settings")
            else {"nav_mode": None, "edges_3d": True})
    nav = conf.get("nav_mode") or NAV_MODE
    out = f' data-nav="{nav}" data-edges="{1 if conf.get("edges_3d", True) else 0}"'
    if user is not None and getattr(auth, "users", None) is not None \
            and auth.users.get(user.name) is not None:
        out += f' data-csrf="{auth.sessions.csrf(user.name)}"'
    return out


def avatar_img(name: str, size: int) -> str:
    """A user's avatar as an <img> (the URL changes with the avatar)."""
    acc = auth.users.get(name) if getattr(auth, "users", None) is not None else None
    if acc is None:
        return ""
    a = avatar.valid(acc.avatar) or avatar.default(acc.name)
    return (f'<img class="avatar" src="/avatar/{quote(acc.name)}.svg?v={a["seed"]}{a["hue"]}" '
            f'width="{size}" height="{size}" alt="">')


def _page(title: str, header: str, body: str, slug: str | None = None,
          bar: bool = False, user: User | None = None,
          wait: list[str] | None = None) -> bytes:
    """``wait``: the items whose render reloads the page when it is done."""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head>
<body data-slug="{escape(slug or '')}" data-wait="{escape(' '.join(wait or []))}"{_settings(user)}><header{' class="bar"' if bar else ''}>{header}{'' if bar else '<span class="spacer"></span>'}
<span id="live" class="live"><i></i><span>connecting…</span></span>{_account(user)}</header>
<main>{body}</main><footer class="ver">{escape(version.text())}</footer><script>{JS}</script></body></html>""".encode("utf-8")


def _when(index: dict) -> str:
    return escape((index.get("listed_at") or "").replace("T", " ").replace("+00:00", " UTC"))


def _count(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


def _file_url(slug: str, rev: str, file: str) -> str:
    return f"/files/{quote(slug)}/{quote(rev)}/{quote(file)}"


SEP = " › "
#: More entries than this and a dropdown gets a filter box.
FILTER_FROM = 8


def _folder(item: dict) -> list[str]:
    """An entry's folder path, top first. Older renders stored "A/B"."""
    f = item.get("folder")
    if isinstance(f, list):
        return [str(p) for p in f if str(p).strip()]
    return [p for p in str(f or "").split("/") if p.strip()]


def _natural(text: str) -> list:
    """A sort key: case-insensitive, numbers by value ("View 2" < "View 10")."""
    return [(0, int(t), "") if t.isdigit() else (1, 0, t)
            for t in re.split(r"(\d+)", text.casefold()) if t]


def _by_name(items: list[tuple[int, dict]]) -> list[tuple[int, dict]]:
    """Saved views (index, view) by folder, then name, alphabetically; the
    views outside any folder after those in folders, as the dropdown shows
    them. The index stays the document's (``?view=N``)."""
    return sorted(items, key=lambda iv: (not _folder(iv[1]),
                                          [_natural(p) for p in _folder(iv[1])],
                                          _natural(str(iv[1].get("name", "")))))


def _path_json(path: list[str]) -> str:
    """A folder path as the browser's JSON.stringify writes it (compared as
    text by the tree's script)."""
    return json.dumps(path, ensure_ascii=False, separators=(",", ":"))


def _dropdown(label: str, entries: list[tuple[str, str, list[str]]],
              current: str = "", attrs: dict[str, str] | None = None) -> str:
    """One dropdown of the top bar: ``entries`` are (link, name, folder
    path) in document order, shown as a folder tree – in each folder its
    subfolders first, then its entries, as IngeTrazo's explorers do; the
    entries outside any folder come last, under "No folder". The entry
    whose link is ``current`` is marked and named in the closed dropdown;
    without one, it shows how many entries there are. ``attrs``: extra
    HTML attributes of an entry, by its link."""
    if not entries:
        return ""
    attrs = attrs or {}
    tree: dict = {"sub": {}, "items": []}
    for link, name, path in entries:
        node = tree
        for part in path:
            node = node["sub"].setdefault(part, {"sub": {}, "items": []})
        node["items"].append((link, name, path))
    rows: list[str] = []

    def item(link: str, name: str, path: list[str], depth: int) -> None:
        on = ' class="on" aria-current="page"' if link == current else ""
        rows.append(f'<a href="{escape(link)}"{on} style="--d:{depth}" '
                    f'data-folder="{escape(SEP.join(path))}" '
                    f'data-in="{escape(_path_json(path))}"{attrs.get(link, "")}>'
                    f'{escape(name)}</a>')

    def walk(node: dict, depth: int, at: list[str]) -> None:
        for name, sub in node["sub"].items():
            rows.append(f'<div class="f" style="--d:{depth}" '
                        f'data-in="{escape(_path_json(at))}" '
                        f'data-p="{escape(_path_json(at + [name]))}">{escape(name)}</div>')
            walk(sub, depth + 1, at + [name])
        if depth:
            for e in node["items"]:
                item(*e, depth)

    walk(tree, 0, [])
    if tree["items"]:
        if tree["sub"]:
            rows.append('<div class="f none" style="--d:0">No folder</div>')
        for e in tree["items"]:
            item(*e, 1 if tree["sub"] else 0)
    filt = ('<input class="dd-filter" type="search" placeholder="Filter…" '
            f'aria-label="Filter {escape(label.lower())}s">' if len(entries) > FILTER_FROM else "")
    # List (every level at once) or tree (one level, folders to step into):
    # a switch in the panel, kept per browser, for every dropdown alike.
    mode = ('<button class="dd-mode" type="button" title="Show the folders as a list '
            'or step through them as a tree">Tree</button>' if tree["sub"] else "")
    cur = f'<span class="cur muted">{len(entries)}</span>'
    for link, name, path in entries:
        if link == current:
            where = escape(SEP.join(path) + SEP) if path else ""
            cur = (f'<span class="cur" title="{where}{escape(name)}">'
                   + (f'<span class="p">{where}</span>' if where else "")
                   + f'{escape(name)}</span>')
            break
    return (f'<details class="dd" data-kind="{escape(label.lower())}"><summary>'
            f'<span class="k">{escape(label)}</span>{cur}</summary>'
            f'<div class="dd-panel"><div class="dd-tools">{filt}{mode}</div>'
            '<div class="dd-up" hidden></div>'
            f'<div class="dd-list">{"".join(rows)}</div>'
            '<div class="dd-empty" hidden>Nothing matches.</div></div></details>')


def _dropdown_3d(idx: dict, current: str, query: dict) -> str:
    """The 3D dropdown: the whole model, then the saved views as cameras,
    in the saved views' folders. On the 3D page a pick turns the camera
    without reloading (view3d.py); elsewhere it opens the 3D page there."""
    paths = {v["name"]: _folder(v) for v in idx.get("views", [])}
    entries = [("?3d=1", "Whole model", [])]
    attrs = {"?3d=1": ' data-cam="0"'}
    cams = [(i, {"name": str(c.get("name", "")), "folder": paths.get(c.get("name"), [])})
            for i, c in enumerate(idx.get("cameras") or [])]
    for i, c in _by_name(cams):
        link = f"?3d=1&cam={i + 1}"
        entries.append((link, c["name"], c["folder"]))
        attrs[link] = f' data-cam="{i + 1}"'
    if current:
        raw = (query.get("cam") or [""])[0]
        current = (f"?3d=1&cam={raw}" if raw.isdigit()
                   and 1 <= int(raw) <= len(idx.get("cameras") or []) else "?3d=1")
    return _dropdown("3D", entries, current, attrs)


def _pending(text: str) -> str:
    return f'<div class="pending"><span>{escape(text)}</span></div>'


def _problems(lines: list, title: str = "Some parts did not render:") -> str:
    lines = [str(x) for x in lines if x]
    if not lines:
        return ""
    return (f'<div class="errors"><strong>{escape(title)}</strong><br>'
            + "<br>".join(escape(x) for x in lines) + "</div>")


def _reader(user: User | None):
    """Whether ``user`` may see a model, by its name from the data folder
    (their shares, mcp_http/shares.py). Without a user list: everyone."""
    if user is None or getattr(auth, "users", None) is None:
        return lambda name: True
    acc = auth.users.get(user.name)
    return lambda name: shares.can_read(acc, name)


def _folder_rel(f) -> str:
    return "" if f.root == folders.DATA_DIR else folders.display_name(f.root)


def overview(user: User | None = None) -> bytes:
    """Every model, folder by folder, each with a small preview. A model
    without a current preview gets one rendered (``PREVIEW`` priority)."""
    may = _reader(user)
    # A folder shows when the user may see it, or something in it.
    groups: dict[str, list[str]] = {f.name: [] for f in folders.FOLDERS
                                    if may(_folder_rel(f) or "*")}
    for m in renderer.models():
        if not may(m["name"]):
            continue
        idx, slug = m["index"], m["slug"]
        if not m["fresh"] or renderer.due(idx, "preview"):
            renderer.request(slug, "preview", PREVIEW)
        thumb = ""
        st = renderer.state(idx, "preview")
        old = (idx.get("prev") or {}).get("files", {}).get("preview")
        if st.get("file"):
            thumb = _file_url(slug, idx["rev"], st["file"])
        elif old:
            thumb = _file_url(slug, idx["prev"]["rev"], old)
        if thumb:
            img = f'<img src="{thumb}" alt="" loading="lazy">'
        elif st.get("error") and not renderer.due(idx, "preview"):
            img = '<span class="muted">no preview</span>'
        else:
            img = '<span class="muted">preview…</span>'
        if m["rendering"]:
            status = "rendering…"
        elif idx.get("errors"):
            status = "could not be opened"
        elif idx:
            status = (f'{_count(len(idx.get("sheets", [])), "sheet")} · '
                      f'{_count(len(idx.get("views", [])), "view")} · {_when(idx)}')
        else:
            status = "not opened yet"
        groups.setdefault(m["folder"], []).append(
            f'<a class="card" href="/m/{quote(slug)}"><div class="thumb">{img}</div>'
            f'<div class="body"><div class="name">{escape(m["rel"])}</div>'
            f'<div class="sub">{status}</div></div></a>')
    if not any(groups.values()):
        body = '<p class="empty">No .igz files in the model folders yet.</p>'
    elif len(groups) == 1:
        body = f'<div class="grid">{"".join(next(iter(groups.values())))}</div>'
    else:
        modes = {f.name: f.mode for f in folders.FOLDERS}
        body = "".join(
            f'<section class="folder"><h2>{escape(name)}'
            + (' <span class="tag">read-only</span>' if modes.get(name) == "ro" else "")
            + "</h2>"
            + (f'<div class="grid">{"".join(cards)}</div>' if cards
               else '<p class="muted">No models.</p>') + "</section>"
            for name, cards in groups.items())
    return _page(site.title(), f"<h1>{escape(site.title())}</h1>", body, user=user,
                 wait=["preview"])


def _pick(query: dict, sheets: list, views: list,
          has_3d: bool = False) -> tuple[str, int]:
    """The entry a model page shows: ``?sheet=N`` or ``?view=N`` (1-based,
    as IngeTrazo counts), or ``?3d=1`` the model in 3D. Without one, or
    with one that no longer exists (the model changed), the first sheet,
    else the first view, else the 3D view."""
    if has_3d and (query.get("3d") or [""])[0] not in ("", "0"):
        return "3d", 0
    for kind, items in (("sheet", sheets), ("view", views)):
        raw = (query.get(kind) or [""])[0]
        if raw.isdigit() and 1 <= int(raw) <= len(items):
            return kind, int(raw) - 1
    if not sheets and not views and has_3d:
        return "3d", 0
    return ("sheet", 0) if sheets else ("view", 0)


def _opening(slug: str, user: User | None, text: str = "Opening the model…") -> bytes:
    return _page(site.title(), '<a class="btn" href="/">← All models</a>',
                 f'<p class="empty">{escape(text)} This page refreshes when it is done.</p>',
                 slug, user=user, wait=["list"])


def model_page(slug: str, user: User | None = None,
               query: dict | None = None) -> bytes | None:
    """One model: the sheet or saved view picked in the top bar, one at a
    time (``?sheet=N`` / ``?view=N``), with Prev/Next through all of them.
    What is on screen is rendered now if it was not yet, its neighbours
    next; until then the page shows the model's last picture of it, if
    there is one."""
    m = renderer.model(slug)
    if m is None or not _reader(user)(m.name):
        return None
    wait: list[str] = []
    if not renderer.fresh(slug):
        renderer.request(slug, "list", NOW)
        wait.append("list")
    idx = renderer.index(slug)
    if idx is None:
        return _opening(slug, user)
    sheets, views = idx.get("sheets", []), idx.get("views", [])
    has_3d = GLB_MAX_MB > 0 and not idx.get("errors")
    kind, pos = _pick(query or {}, sheets, views, has_3d)
    # Every entry in the order Prev/Next walks: the sheets in document
    # order, then the views alphabetically.
    sorted_views = _by_name(list(enumerate(views)))
    entries = ([("sheet", i, s) for i, s in enumerate(sheets)]
               + [("view", i, v) for i, v in sorted_views])

    def link(k: str, i: int) -> str:
        return f"?{k}={i + 1}"

    current = "?3d=1" if kind == "3d" else link(kind, pos)
    sheet_nav = [(link("sheet", i), s["name"], _folder(s)) for i, s in enumerate(sheets)]
    view_nav = [(link("view", i), v["name"], _folder(v)) for i, v in sorted_views]

    content = _problems(idx.get("errors") or [], "The model could not be opened:")
    step = prefetch = ""
    if kind == "3d":
        st = renderer.state(idx, "glb")
        if st.get("file"):
            content += view3d(_file_url(slug, idx["rev"], st["file"]),
                              idx.get("cameras") or [], st.get("mb"),
                              idx.get("layer_tree") or {})
        elif st.get("note"):
            content += f'<p class="empty">{escape(st["note"])}</p>'
        elif renderer.due(idx, "glb"):
            renderer.request(slug, "glb", NOW)
            wait.append("glb")
            content += _pending("Preparing the 3D model…")
        else:
            content += _problems([st.get("error")], "The 3D model could not be made:")
    elif entries:
        at = next(n for n, (k, i, _) in enumerate(entries) if (k, i) == (kind, pos))
        item = entries[at][2]
        key = f"{kind}:{pos + 1}"
        renderer.viewed(slug, key, item["name"])
        st = renderer.state(idx, key)
        path = _folder(item)
        extra = ("" if kind == "view" or item.get("printed", True)
                 else ' <span class="muted">(not printed)</span>')
        where = f'<span class="muted">{escape(SEP.join(path))}</span>' if path else ""
        count = len(sheets) if kind == "sheet" else len(views)
        before = idx.get("prev") or {}
        old = (before.get("files") or {}).get(f"{kind}:{item['name']}")
        url = ""
        if st.get("file"):
            url = _file_url(slug, idx["rev"], st["file"])
        else:
            if old:
                url = _file_url(slug, before["rev"], old)
            if renderer.due(idx, key):
                renderer.request(slug, key, NOW)
                wait.append(key)
                if old:
                    extra += ' <span class="muted">(updating…)</span>'
            elif st.get("error"):
                content += _problems([st["error"]], f"This {kind} did not render:")
        content += _problems(st.get("warnings") or [])
        if url:
            img = (f'<a class="img" href="{url}" target="_blank" title="Open full size">'
                   f'<img src="{url}" alt="{escape(item["name"])}"></a>')
        else:
            img = _pending("Rendering…" if key in wait else "not rendered")
        content += (f'<figure class="one">{img}<figcaption><strong>{escape(item["name"])}</strong>'
                    f'{extra}<span class="muted">{kind.capitalize()} {pos + 1} of {count}</span>'
                    f'<span class="spacer"></span>{where}</figcaption></figure>')
        if len(entries) > 1:
            prev_k, prev_i, prev = entries[at - 1]
            next_k, next_i, nxt = entries[(at + 1) % len(entries)]
            step = (f'<span class="step"><a class="btn" id="prev" href="{link(prev_k, prev_i)}" '
                    f'title="Previous: {escape(prev["name"])} (←)" aria-label="Previous">‹</a>'
                    f'<a class="btn" id="next" href="{link(next_k, next_i)}" '
                    f'title="Next: {escape(nxt["name"])} (→)" aria-label="Next">›</a></span>')
            # The neighbours: rendered next, and loaded in the background
            # once they are, so stepping is instant.
            for k, i in ((prev_k, prev_i), (next_k, next_i)):
                n_key = f"{k}:{i + 1}"
                n_st = renderer.state(idx, n_key)
                if n_st.get("file"):
                    prefetch += (f'<link rel="prefetch" '
                                 f'href="{_file_url(slug, idx["rev"], n_st["file"])}">')
                elif renderer.due(idx, n_key):
                    renderer.request(slug, n_key, NEXT)
    elif not idx.get("errors"):
        content += '<p class="empty">This model has no sheets and no saved views.</p>'
    pdf = ('<a class="btn" href="?pdf=1" target="_blank" title="All sheets as one PDF">PDF</a>'
           if WITH_PDF and sheets else "")
    navs = _dropdown("View", view_nav, current)
    if has_3d:
        navs += _dropdown_3d(idx, current if kind == "3d" else "", query or {})
    navs += _dropdown("Sheet", sheet_nav, current)
    header = (f'<a class="btn" href="/" title="All models">←</a>'
              f'<h1 title="{escape(idx["name"])}">{escape(idx["name"])}</h1>'
              + (f'<nav class="navs">{navs}</nav>' if navs else "") + step
              + f'<span class="spacer"></span><span class="meta">read {_when(idx)}</span>{pdf}')
    return _page(f'{idx["name"]} – {site.title()}', header, prefetch + content, slug,
                 bar=True, user=user, wait=wait)


def pdf_page(slug: str, user: User | None = None) -> tuple[bytes | None, str]:
    """``?pdf=1``: (a page, "") while the sheets' PDF is made, or (None,
    its URL) when it is there."""
    if not renderer.fresh(slug):
        renderer.request(slug, "list", NOW)
        return _opening(slug, user, "Reading the model before making the PDF…"), ""
    idx = renderer.index(slug)
    if idx is None:
        return _opening(slug, user), ""
    st = renderer.state(idx, "pdf")
    if st.get("file"):
        return None, _file_url(slug, idx["rev"], st["file"])
    back = f'<a class="btn" href="/m/{quote(slug)}">← {escape(idx["name"])}</a>'
    if not WITH_PDF or not idx.get("sheets"):
        return _page(site.title(), back, '<p class="empty">There is no PDF of this model.</p>',
                     slug, user=user), ""
    if renderer.due(idx, "pdf"):
        renderer.request(slug, "pdf", NOW)
        return _page(site.title(), back, _pending("Making the PDF of all sheets…"),
                     slug, user=user, wait=["pdf"]), ""
    return _page(site.title(), back, _problems([st.get("error")], "The PDF could not be made:"),
                 slug, user=user), ""


COOKIE = "itz_viewer"


def _safe_next(value: str) -> str:
    """Only a path on this server (no //host, no /\\host, no scheme)."""
    return (value if value.startswith("/") and not value.startswith(("//", "/\\"))
            else "/")


LOGIN_CSS = """
.login{max-width:340px;margin:12vh auto;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:24px;box-shadow:var(--shadow)}
.login h1{font-size:18px;margin:0 0 16px}.login label{display:block;font-size:13px;color:var(--muted);margin:12px 0 4px}
.login input{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:6px;
background:var(--bg);color:var(--fg);font:inherit}
.login button,.login .go{display:block;text-align:center;margin-top:18px;width:100%;padding:9px;border:0;border-radius:6px;
background:var(--accent);color:#fff;font:inherit;font-weight:600;cursor:pointer}
.login .go:hover{text-decoration:none}.login p{margin:0 0 8px}
.err{color:#c0392b;font-size:14px;margin:0 0 8px}
.login .guest{margin:0}.login button.alt{background:transparent;color:var(--accent);border:1px solid var(--line);font-weight:500}
.login button.alt:hover{border-color:var(--accent)}
"""


def _card(title: str, inner: str) -> bytes:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} – {escape(site.title())}</title><style>{CSS}{LOGIN_CSS}</style></head>
<body><main><div class="login"><h1>{escape(site.title())}</h1>{inner}</div></main></body></html>""".encode("utf-8")


def _guest_button(nxt: str) -> str:
    """"Log in as guest" (VIEWER_GUEST), under the login."""
    if not getattr(auth, "guest", False):
        return ""
    return (f'<form method="post" action="/login/guest" class="guest">'
            f'<input type="hidden" name="next" value="{escape(nxt)}">'
            '<button type="submit" class="alt">Log in as guest</button></form>')


def login_page(error: str, nxt: str) -> bytes:
    err = f'<p class="err">{escape(error)}</p>' if error else ""
    if auth.mode == "oidc":                    # a choice: the provider or a guest
        go = "/auth/login?" + urlencode({"next": nxt})
        return _card("Log in", f'{err}<a class="go" href="{escape(go)}">Log in</a>'
                               + _guest_button(nxt))
    return _card("Log in", f"""<form method="post" action="/login">{err}
<input type="hidden" name="next" value="{escape(nxt)}">
<label for="u">User</label><input id="u" name="user" autocomplete="username" autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">
<button type="submit">Log in</button></form>""" + _guest_button(nxt))


def _render_action(form: dict) -> tuple[str, str]:
    """``/admin/renders``: render what is missing, of one model or all."""
    action = (form.get("action") or [""])[0]
    if action == "render-all":
        for m in renderer.models():
            renderer.request(m["slug"], "all", BACKGROUND)
        return "Everything not rendered yet is queued.", ""
    if action == "render":
        slug = (form.get("slug") or [""])[0]
        m = renderer.model(slug) if _SAFE.match(slug) else None
        if m is None:
            return "", "No such model."
        renderer.request(slug, "all", NEXT)
        return f"{m.name}: everything not rendered yet is queued.", ""
    return "", "Unknown action."


def message_page(text: str, link: str = "", label: str = "", extra: str = "") -> bytes:
    go = f'<a class="go" href="{escape(link)}">{escape(label)}</a>' if link else ""
    return _card(label or "Viewer", f"<p>{escape(text)}</p>{extra}{go}")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ingetrazo-viewer"

    def parse_request(self):
        # One handler serves every request of a kept-alive connection.
        self._who: User | None = None
        self._t0 = time.monotonic()
        return super().parse_request()

    def log_message(self, fmt, *args):
        if not self.path.startswith(("/healthz", "/files/", "/static/")):
            line = audit.redact(fmt % args)      # an access link's token stays out of the log
            who = getattr(self, "_who", None)
            sys.stderr.write("[viewer] %s%s %s\n" % (
                self._client()[0], f" {who.name}" if who else "", line))

    def log_request(self, code="-", size="-"):
        super().log_request(code, size)
        path = getattr(self, "path", "")
        if path.startswith(audit.QUIET):
            return
        try:
            status = int(code)
        except (TypeError, ValueError):
            status = None
        self._audit("access", method=self.command, path=path, status=status,
                    ms=round((time.monotonic() - getattr(self, "_t0", time.monotonic())) * 1000))

    def _client(self) -> tuple[str, str]:
        """(the client's address, an unverified X-Forwarded-For)."""
        headers = getattr(self, "headers", None)
        return audit.client(self.client_address[0],
                            headers.get("X-Forwarded-For", "") if headers else "")

    def _audit(self, kind: str, user: User | str | None = None, **fields) -> None:
        """One audit log entry (viewer/audit.py) about this request."""
        who = user or getattr(self, "_who", None)
        ip, fwd = self._client()
        if isinstance(who, str):
            fields.setdefault("user", who)
        elif who is not None:
            fields.setdefault("user", who.name)
            fields.setdefault("source", who.source)
        audit.record(kind, ip=ip, fwd=fwd, **fields)

    def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # ---- authentication ------------------------------------------------------
    # Browsers get a login page (local) or the provider's (oidc), then a
    # session cookie: embedded browsers (VS Code's, many WebViews) never
    # show the Basic-auth dialog and only print the 401. Scripts and curl
    # use Basic auth (local). A proxy (proxy) names the user on every request.
    def _cookie_user(self) -> User | None:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = jar.get(COOKIE)
        return None if morsel is None else auth.sessions.read(morsel.value)

    def _basic_user(self) -> User | None:
        value = self.headers.get("Authorization", "")
        if not value.startswith("Basic "):
            return None
        try:
            user, _, pw = base64.b64decode(value[6:]).decode().partition(":")
        except ValueError:
            return None
        return auth.login(user, pw)

    def _bearer_user(self) -> User | None:
        """An access link's token as ``Authorization: Bearer itv_…`` (scripts)."""
        value = self.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            return None
        return auth.link_login(value[7:])

    def _user(self) -> User | None:
        if auth.mode == "none":
            return User("anonymous")
        if auth.mode == "proxy":
            return auth.from_proxy(self.client_address[0], self.headers)
        user = self._cookie_user()
        if user is not None:
            # As the user list has them now (switched off, another role).
            return auth.current(user)
        bearer = self._bearer_user()
        if bearer is not None:
            return bearer
        if auth.mode == "local":
            return self._basic_user()
        return None

    def _authorised(self, path: str) -> User | None:
        user = self._user()
        if user is not None:
            if auth.mode != "none":
                self._who = user
            return user
        wants_html = "text/html" in self.headers.get("Accept", "")
        page = wants_html and not path.startswith(("/files/", "/events"))
        target = self.path if self.path.startswith("/") else "/"
        old = self._cookie_user()
        if old is not None and old.source == "link":
            clear = {"Set-Cookie": f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"}
            if page:
                self._html(403, message_page(
                    "This access link no longer works: it was switched off, replaced, "
                    "removed or has expired. Ask whoever gave it to you for a new one."), clear)
            else:
                self._send(403, b"access link no longer valid\n", "text/plain", clear)
            return None
        if self._is_disabled():
            if page:
                self._html(403, message_page(
                    "Your account may not use this viewer (switched off, or MCP only). "
                    "Ask an admin of this viewer.",
                    "/logout" if auth.mode != "proxy" else "", "Log out"),
                    {"Set-Cookie": f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"})
            else:
                self._send(403, b"account switched off\n", "text/plain")
        elif auth.mode == "proxy":
            if page:
                self._html(401, message_page(
                    "This viewer is reached through its login proxy, which did "
                    "not name a user."))
            else:
                self._send(401, b"authentication required (through the proxy)\n",
                           "text/plain")
        elif page:
            where = "/login" if auth.mode == "local" or auth.guest else "/auth/login"
            self._send(303, b"", "text/plain",
                       {"Location": where + "?next=" + quote(target, safe="")})
        elif auth.mode == "local":
            self._send(401, b"authentication required\n", "text/plain",
                       {"WWW-Authenticate": f'Basic realm="{site.title()}", charset="UTF-8"'})
        else:
            self._send(401, b"authentication required\n", "text/plain")
        return None

    def _is_disabled(self) -> bool:
        """Whether whoever asks is a known user an admin switched off."""
        if auth.mode == "proxy":
            found = auth.proxy.user(self.client_address[0], self.headers)
            return bool(found) and auth.disabled(found[0])
        user = self._cookie_user()
        return user is not None and auth.disabled(user.name)

    def _secure(self) -> bool:
        return (self.headers.get("X-Forwarded-Proto", "").lower() == "https"
                or os.environ.get("VIEWER_COOKIE_SECURE", "").lower() in ("1", "true", "yes")
                or (auth.mode == "oidc" and auth.oidc.redirect_uri.startswith("https://")))

    def _html(self, status: int, body: bytes, extra: dict | None = None):
        self._send(status, body, "text/html; charset=utf-8",
                   {"Cache-Control": "no-store", **(extra or {})})

    def _login_page(self, status: int = 200, error: str = "", nxt: str = "/"):
        self._html(status, login_page(error, nxt))

    def _session_cookie(self, user: User) -> str:
        return (f"{COOKIE}={auth.sessions.issue(user)}; Path=/; HttpOnly; SameSite=Lax; "
                f"Max-Age={auth.sessions.max_age}" + ("; Secure" if self._secure() else ""))

    def _form(self) -> dict:
        length = min(int(self.headers.get("Content-Length") or 0), 16384)
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"),
                        keep_blank_values=True)

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/login" and auth.mode == "local":
            return self._post_login()
        if path == "/login/guest" and auth.guest:
            nxt = _safe_next((self._form().get("next") or ["/"])[0])
            user = auth.guest_login()
            if user is None:
                self._audit("login", user="guest", source="guest", status=403,
                            detail="guests switched off")
                return self._login_page(403, "Guests may not log in at the moment.", nxt)
            self._who = user
            self._audit("login", status=303, detail="guest")
            return self._send(303, b"", "text/plain", {
                "Location": nxt, "Set-Cookie": self._session_cookie(user)})
        if path == "/account/settings" and auth.mode != "none":
            return self._post_settings()
        if path in ("/admin", "/admin/renders", "/account") and auth.mode != "none":
            user = self._authorised(path)
            if user is None:
                return None
            form = self._form()
            if not hmac.compare_digest((form.get("csrf") or [""])[0],
                                       auth.sessions.csrf(user.name)):
                return self._html(403, message_page("The form expired; open it again.",
                                                    path, "Back"))
            if path == "/admin/renders":
                if not user.admin:
                    return self._send(403, b"admins only\n", "text/plain")
                note, error = _render_action(form)
                self._admin_audit(form, note, error)
                return self._html(400 if error else 200, admin.renders_page(
                    auth, user, renderer.status(), note, error, site.title()))
            if path == "/admin":
                if not user.admin:
                    return self._send(403, b"admins only\n", "text/plain")
                note, error = admin.act(auth, user, form)
                self._admin_audit(form, note, error)
                if (form.get("action") or [""])[0] == "shares":
                    return self._html(400 if error else 200, admin.shares_page(
                        auth, user, (form.get("name") or [""])[0], note, error, site.title()))
                return self._html(400 if error else 200,
                                  admin.page(auth, user, note, error, site.title()))
            note, error = admin.act_account(auth, user, form)
            self._admin_audit(form, note, error, prefix="account: ")
            return self._html(400 if error else 200,
                              admin.account_page(auth, user, note, error, site.title()))
        return self._send(404, b"not found\n", "text/plain")

    def _admin_audit(self, form: dict, note: str, error: str, prefix: str = "") -> None:
        """A change in the admin panel (or one's own account), and its outcome."""
        def get(key: str) -> str:
            return (form.get(key) or [""])[0]
        if note.startswith("TOKEN:"):
            note = "a new token was made"
        elif note.startswith("LINK:"):
            note = f"a new access link for {note[5:].partition(':')[0]}"
        self._audit("admin", method="POST", path=urlsplit(self.path).path,
                    status=400 if error else 200,
                    action=prefix + (get("action") or "?"),
                    target=(get("name") or get("slug")).strip()[:120],
                    detail=error or note)

    def _post_settings(self):
        """A setting the page's script changed: JSON back, all settings."""
        user = self._authorised("/account/settings")
        if user is None:
            return None
        form = self._form()
        if not hmac.compare_digest((form.get("csrf") or [""])[0],
                                   auth.sessions.csrf(user.name)):
            return self._send(403, b'{"error": "csrf"}', "application/json")
        changes = {k: admin.setting_value(k, v[0]) for k, v in form.items() if k != "csrf"}
        try:
            conf = auth.users.set_settings(user.name, changes)
        except UserError as exc:
            return self._send(400, json.dumps({"error": str(exc)}).encode(), "application/json")
        return self._send(200, json.dumps(conf).encode(), "application/json",
                          {"Cache-Control": "no-store"})

    def _post_login(self):
        form = self._form()
        name = (form.get("user") or [""])[0].strip()
        pw = (form.get("password") or [""])[0]
        nxt = _safe_next((form.get("next") or ["/"])[0])
        user = auth.login(name, pw)
        if user is None and auth.users.authenticate(name, pw) is not None:
            self._audit("login", user=name[:64], source="local", status=403,
                        detail="password right, but no web viewer for this account")
            return self._login_page(403, "This account may not use the web viewer.", nxt)
        if user is not None:
            self._who = user
            self._audit("login", status=303, detail="password")
            return self._send(303, b"", "text/plain", {
                "Location": nxt, "Set-Cookie": self._session_cookie(user)})
        self._audit("login", user=name[:64], source="local", status=401,
                    detail="wrong user name or password")
        time.sleep(0.7)                          # slows down guessing
        return self._login_page(401, "Wrong user name or password.", nxt)

    def do_HEAD(self):
        self.do_GET()

    def _account_routes(self, path: str, query: dict) -> bool:
        """/login, /logout and the OIDC flow; True when one answered."""
        nxt = _safe_next((query.get("next") or ["/"])[0])
        clear = f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        if path == "/login":
            if auth.mode == "local" or auth.guest:
                self._login_page(nxt=nxt)
            elif auth.mode == "oidc":
                self._send(303, b"", "text/plain",
                           {"Location": "/auth/login?" + urlencode({"next": nxt})})
            else:
                self._send(303, b"", "text/plain", {"Location": nxt})
            return True
        if path.startswith("/t/"):
            return self._link_login(path[3:], nxt)
        if path == "/logout":
            link = self._cookie_user()
            if link is not None:
                self._audit("logout", user=link)
            if link is not None and link.source == "link":
                self._html(200, message_page(
                    "You are logged out. Open your access link again to come back."),
                    {"Set-Cookie": clear})
                return True
            if auth.mode == "local":
                self._send(303, b"", "text/plain",
                           {"Location": "/login", "Set-Cookie": clear})
            elif auth.mode == "oidc" and self._cookie_user() is not None \
                    and self._cookie_user().source == "guest":
                self._send(303, b"", "text/plain", {"Location": "/login", "Set-Cookie": clear})
            elif auth.mode == "oidc":
                end = auth.oidc.end_session()
                extra = (f'<p class="muted"><a href="{escape(end)}?'
                         f'{escape(urlencode({"client_id": auth.oidc.client_id}))}">'
                         "Also log out of the identity provider</a></p>" if end else "")
                self._html(200, message_page("You are logged out of the viewer.",
                                             "/auth/login", "Log in again", extra),
                           {"Set-Cookie": clear})
            elif auth.mode == "proxy" and auth.proxy.logout_url:
                self._send(303, b"", "text/plain", {"Location": auth.proxy.logout_url})
            else:
                self._send(303, b"", "text/plain", {"Location": "/"})
            return True
        if auth.mode != "oidc" or path not in ("/auth/login", "/auth/callback"):
            return False
        try:
            if path == "/auth/login":
                self._send(303, b"", "text/plain", {"Location": auth.oidc.start(nxt)})
                return True
            if query.get("error"):
                raise ValueError(f"the provider said: {query['error'][0]} "
                                 + (query.get("error_description") or [""])[0])
            name, groups, nxt = auth.oidc.finish((query.get("code") or [""])[0],
                                                 (query.get("state") or [""])[0])
        except (OSError, ValueError) as exc:
            log(f"viewer: OIDC login failed: {exc}")
            self._audit("login", source="oidc", status=400, detail=f"OIDC login failed: {exc}")
            self._html(502 if isinstance(exc, OSError) else 400, message_page(
                f"The login did not work: {exc}", "/auth/login", "Try again"))
            return True
        user = auth.logged_in(name, groups)
        if user is None:
            self._audit("login", user=name[:64], source="oidc", status=403,
                        detail="account switched off or refused")
            self._html(403, message_page(
                "Your account is switched off. Ask an admin of this viewer."))
            return True
        self._who = user
        self._audit("login", status=303, detail="OIDC")
        self._send(303, b"", "text/plain",
                   {"Location": _safe_next(nxt), "Set-Cookie": self._session_cookie(user)})
        return True

    def _link_login(self, token: str, nxt: str) -> bool:
        """``/t/<token>``: an access link logs the browser in, then the
        address without the token (it stays out of history and referrers)."""
        if not getattr(auth, "links", False):
            self._send(404, b"not found\n", "text/plain")
            return True
        user = auth.link_login(token)
        if user is None:
            self._audit("login", source="link", status=403,
                        detail="access link not valid (wrong, switched off or expired)")
            time.sleep(0.7)                      # slows down guessing
            self._html(403, message_page(
                "This access link does not work (any more). Ask whoever gave it to you "
                "for a new one."), {"Referrer-Policy": "no-referrer"})
            return True
        self._who = user
        self._audit("login", status=303, detail="access link")
        self._send(303, b"", "text/plain", {
            "Location": nxt, "Set-Cookie": self._session_cookie(user),
            "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})
        return True

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/healthz":
            return self._health()
        if self._account_routes(path, parse_qs(parts.query)):
            return None
        user = self._authorised(path)
        if user is None:
            return None
        html = "text/html; charset=utf-8"
        nocache = {"Cache-Control": "no-store"}
        if path == "/":
            return self._send(200, overview(user), html, nocache)
        if path == "/admin" and auth.mode != "none":
            if not user.admin:
                return self._html(403, message_page("Only admins manage the users.", "/", "Back"))
            return self._html(200, admin.page(auth, user, title=site.title()))
        if path == "/admin/renders" and auth.mode != "none":
            if not user.admin:
                return self._html(403, message_page("Only admins see the renders.", "/", "Back"))
            return self._send(200, admin.renders_page(auth, user, renderer.status(),
                                                      title=site.title()), html, nocache)
        if path in ("/admin/log", "/admin/log.jsonl") and auth.mode != "none":
            if not user.admin:
                return self._html(403, message_page("Only admins see the log.", "/", "Back"))
            query = parse_qs(parts.query)
            if path.endswith(".jsonl"):
                return self._send(200, admin.log_download(query), "application/x-ndjson",
                                  {"Cache-Control": "no-store", "Content-Disposition":
                                   'attachment; filename="viewer-audit.jsonl"'})
            return self._html(200, admin.log_page(auth, user, query, title=site.title()))
        if path == "/admin/shares" and auth.mode != "none":
            if not user.admin:
                return self._html(403, message_page("Only admins manage the users.", "/", "Back"))
            query = parse_qs(parts.query)
            name = (query.get("name") or [""])[0]
            check = (query.get("check") or [""])[0]
            return self._html(200, admin.shares_page(auth, user, name, title=site.title(),
                                                     check=check))
        if path.startswith("/avatar/") and path.endswith(".svg") and auth.mode != "none":
            from urllib.parse import unquote
            acc = auth.users.get(unquote(path[8:-4]))
            if acc is None:
                return self._send(404, b"not found\n", "text/plain")
            return self._send(200, avatar.svg(acc.name, acc.avatar).encode(),
                              "image/svg+xml", {"Cache-Control": "private, max-age=86400",
                                                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        if path == "/account" and auth.mode != "none":
            return self._html(200, admin.account_page(auth, user, title=site.title()))
        if path.startswith("/m/"):
            slug = path[3:]
            query = parse_qs(parts.query)
            m = renderer.model(slug) if _SAFE.match(slug) else None
            if m is None or not _reader(user)(m.name):
                return self._send(404, b"no such model\n", "text/plain")
            if (query.get("pdf") or [""])[0] not in ("", "0"):
                page, url = pdf_page(slug, user)
                if page is None:
                    return self._send(303, b"", "text/plain", {"Location": url})
                return self._send(200, page, html, nocache)
            page = model_page(slug, user, query)
            if page is None:
                return self._send(404, b"no such model\n", "text/plain")
            return self._send(200, page, html, nocache)
        if path.startswith("/files/"):
            m = renderer.model(path[7:].split("/")[0])
            if m is None or not _reader(user)(m.name):
                return self._send(404, b"not found\n", "text/plain")
            return self._file(path[7:])
        if path.startswith("/static/three/"):
            return self._static(path[len("/static/three/"):])
        if path == "/events":
            return self._events(user)
        if path == "/version":
            return self._send(200, (json.dumps(version.info()) + "\n").encode(),
                              "application/json", nocache)
        return self._send(404, b"not found\n", "text/plain")

    def _file(self, rest: str):
        parts = rest.split("/")
        if len(parts) != 3 or not all(_SAFE.match(p) and not p.startswith(".")
                                      for p in parts):
            return self._send(404, b"not found\n", "text/plain")
        f = CACHE_DIR.joinpath(*parts)
        if not f.is_file():
            return self._send(404, b"not found\n", "text/plain")
        ctype = {"png": "image/png", "pdf": "application/pdf",
                 "svg": "image/svg+xml", "glb": "model/gltf-binary"}.get(f.suffix[1:].lower(), "application/octet-stream")
        # A render's folder never changes: cache it for good.
        return self._send(200, f.read_bytes(), ctype,
                          {"Cache-Control": "private, max-age=31536000, immutable"})

    def _static(self, rest: str):
        """The 3D view's library (three.js, fetched at image build time)."""
        parts = rest.split("/")
        if not parts or not all(_SAFE.match(p) and p not in (".", "..") for p in parts):
            return self._send(404, b"not found\n", "text/plain")
        f = THREE_DIR.joinpath(*parts)
        if not f.is_file():
            return self._send(404, b"not found\n", "text/plain")
        ctype = ("text/javascript; charset=utf-8" if f.suffix == ".js"
                 else "text/plain; charset=utf-8")
        return self._send(200, f.read_bytes(), ctype,
                          {"Cache-Control": "private, max-age=86400"})

    def _events(self, user: User | None = None):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        cond = renderer.changed
        with cond:
            seen = renderer.generation
        try:
            self.wfile.write(b"retry: 3000\n\n")
            self.wfile.flush()
            while True:
                with cond:
                    cond.wait_for(lambda: renderer.generation != seen, timeout=15)
                # Every event since the last one sent: a "done" may come
                # right before an "idle".
                events = renderer.events_since(seen)
                may = _reader(user)              # shares may change meanwhile
                for event in events:
                    m = renderer.model(event["slug"]) if event.get("slug") else None
                    if event.get("slug") and m is not None and not may(m.name):
                        continue
                    self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                if events:
                    seen = events[-1]["generation"]
                else:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            return None

    def _health(self):
        stale = time.monotonic() - renderer.heartbeat
        if not renderer.alive():
            status, body = 503, {"status": "ingetrazo not running"}
        elif renderer.rendering is None and stale > max(60.0, POLL * 20):
            status, body = 503, {"status": "render loop stalled"}
        else:
            status, body = 200, {"status": "rendering" if renderer.rendering else "ok"}
        self._send(status, json.dumps(body).encode(), "application/json",
                   {"Cache-Control": "no-store"})


class Server(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        """An exception in a request: on stderr as before, and in the audit log."""
        exc = sys.exc_info()[1]
        if not isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            audit.record("error", ip=client_address[0] if client_address else "",
                         detail=f"request failed: {exc!r}")
        super().handle_error(request, client_address)


def main() -> None:
    global renderer, auth
    auth = Auth()                    # a wrong setting stops here, before IngeTrazo
    urls = engine_urls()
    if not urls:
        raise SystemExit("ENGINE_URLS must name the render engine(s) (ingetrazo-docker "
                         "containers, command engine), e.g. http://viewer-engine:8766")
    # One render worker per engine; this container runs no IngeTrazo.
    apps = [RemoteApp(u) for u in urls]
    where = "engines " + ", ".join(urls)
    renderer = Renderer(apps)
    port = int(os.environ.get("VIEWER_PORT", 8080))
    server = Server(("0.0.0.0", port), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()
    log(f"viewer on :{port} (auth: {auth.describe()}); cache {CACHE_DIR}; "
        f"prerender {PRERENDER}; {where}; model folders: "
        + "; ".join(f.describe() for f in folders.FOLDERS))
    for app in apps:
        app.start()
    renderer.run()


if __name__ == "__main__":
    # Run the package's copy: admin.py imports viewer.server, and a second
    # copy of this file (as __main__) would hold auth and renderer while
    # viewer.server's stay unset (NameError on /admin and /account).
    from viewer import server as _server
    _server.main()
