# SPDX-License-Identifier: AGPL-3.0-or-later
"""The viewer's admin panel (``/admin``) and a user's own page
(``/account``, with their settings): plain HTML forms, each with the
session's CSRF token.

Admins add local users (``VIEWER_AUTH_MODE=local``), set a user's role
(unless the provider's admin group decides it), switch users off and on,
set a local user's password, give them folders (``/admin/shares``, see
mcp_http/shares.py), and remove users. They also hand out access links:
a named account for the web viewer only, opened with a link
(``/t/<token>``), with its own folders and an optional last day. The list always keeps one
active admin; an admin cannot switch themself off, remove themself or
take away their own admin role. The owner (``ADMIN_USER``, local login)
always stays an active admin.
"""
from __future__ import annotations

import json
from html import escape
from urllib.parse import quote

from mcp_http import shares as share_mod

from . import audit
from mcp_http.users import ROLES, SETTINGS, UserError

CSS = """
.panel{max-width:960px;margin:0 auto}
.panel h2{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin:24px 0 10px}
.panel table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.panel th,.panel td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:middle}
.panel th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.panel tr:last-child td{border-bottom:0}
.panel .acts>div{display:flex;gap:6px;flex-wrap:wrap}
.panel form.inline{display:inline-flex;gap:6px;align-items:center;margin:0}
.panel input,.panel select{border:1px solid var(--line);background:var(--bg);color:var(--fg);padding:5px 8px;border-radius:6px;font:inherit;font-size:13px}
.panel button{border:1px solid var(--line);background:var(--card);color:var(--fg);padding:5px 10px;border-radius:6px;font:inherit;font-size:13px;cursor:pointer}
.panel button:hover{border-color:var(--accent)}
.panel button.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.panel button.danger:hover{border-color:#c0392b;color:#c0392b}
.panel .add{display:flex;gap:8px;flex-wrap:wrap;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.panel .note{background:color-mix(in srgb,var(--ok) 12%,var(--card));border:1px solid var(--ok);border-radius:8px;padding:8px 12px;margin:12px 0;font-size:14px}
.panel .err{background:color-mix(in srgb,#c0392b 10%,var(--card));border:1px solid #c0392b;border-radius:8px;padding:8px 12px;margin:12px 0;font-size:14px;color:inherit}
.panel .off td:not(.acts){color:var(--muted)}
.panel .avatar-box{display:flex;gap:12px;align-items:center;flex-wrap:wrap}
.panel .rights{display:inline-flex;gap:0}
.panel .right{border:1px solid var(--line);background:var(--card);color:var(--muted);padding:5px 9px;font-size:12px;border-radius:0;text-decoration:line-through}
.panel .rights>:first-child .right,.panel .rights>.right:first-child{border-radius:6px 0 0 6px}
.panel .rights>:last-child .right,.panel .rights>.right:last-child{border-radius:0 6px 6px 0;margin-left:-1px}
.panel .right.on{color:var(--fg);background:color-mix(in srgb,var(--ok) 14%,var(--card));text-decoration:none;font-weight:600}
.panel .token{font-family:ui-monospace,monospace;font-size:13px;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;overflow-wrap:anywhere;user-select:all}
.panel .stack{display:flex;flex-direction:column;gap:10px;max-width:360px;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.panel .stack label{font-size:13px;color:var(--muted)}
.panel .add textarea{flex:1 1 100%;min-height:4.5em;border:1px solid var(--line);background:var(--bg);color:var(--fg);padding:6px 8px;border-radius:6px;font:13px ui-monospace,monospace}
.panel .add label{font-size:13px;color:var(--muted);flex:1 1 100%}
.panel details.help{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 12px;margin:12px 0;font-size:14px}
.panel details.help summary{cursor:pointer;font-weight:600}
.panel details.help code,.panel td code,.panel .add code,.panel .note code{font-family:ui-monospace,monospace;font-size:12.5px;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:0 4px}
.panel details.help table{margin:8px 0}
.panel .st{display:inline-block;font-size:12px;border-radius:4px;padding:1px 7px;border:1px solid var(--line);white-space:nowrap}
.panel .st.rendered{border-color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,var(--card))}
.panel .st.rendering,.panel .st.queued{border-color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,var(--card))}
.panel .st.failed{border-color:#c0392b;background:color-mix(in srgb,#c0392b 12%,var(--card))}
.panel .st.outdated,.panel .st.missing,.panel .st.skipped{color:var(--muted)}
.panel .chips{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.panel details.model{margin:10px 0}
.panel details.model>summary{cursor:pointer;padding:6px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.panel details.model>summary form{margin-left:auto}
.panel td.detail{font-size:12.5px;color:var(--muted);overflow-wrap:anywhere}
.panel .sub{display:flex;gap:6px;margin:4px 0 0}
.panel a.btn.primary{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.panel .filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.panel td.when{white-space:nowrap;font-variant-numeric:tabular-nums}
.panel .st.access{color:var(--muted)}.panel .st.login,.panel .st.logout{border-color:var(--accent)}
.panel .st.admin{border-color:var(--warn);background:color-mix(in srgb,var(--warn) 14%,var(--card))}
.panel .st.error,.panel .st.bad{border-color:#c0392b;background:color-mix(in srgb,#c0392b 12%,var(--card))}
.panel td.req{font-family:ui-monospace,monospace;font-size:12.5px;overflow-wrap:anywhere}
@media (max-width:820px){.panel table,.panel tbody,.panel tr,.panel td{display:block;width:100%}
.panel thead{display:none}.panel tr{border-bottom:1px solid var(--line)}.panel td{border:0;padding:4px 10px}}
"""


def _wrap(title: str, body: str, user, site: str) -> bytes:
    from . import server              # the page frame and the top bar
    header = (f'<a class="btn" href="/" title="All models">←</a>'
              f'<h1>{escape(title)}</h1>')
    return server._page(f"{title} – {site}", header,
                        f'<style>{CSS}</style><div class="panel">{body}</div>', user=user)


def _messages(note: str, error: str) -> str:
    if note.startswith("TOKEN:"):              # a new token: shown once, easy to copy
        return ('<div class="note">Your new token – copy it now, it is shown only once:'
                f'<div class="token">{escape(note[6:])}</div></div>')
    if note.startswith("LINK:"):               # a new access link: shown once
        name, _, token = note[5:].rpartition(":")   # a name may hold ":"
        path = "/t/" + token
        return ('<div class="note">The access link for <strong>' + escape(name)
                + '</strong> – copy it now, it is shown only once:'
                f'<div class="token" id="newlink">{escape(path)}</div>'
                '<script>(function(){const e=document.getElementById("newlink");'
                'e.textContent=location.origin+e.textContent;})()</script>'
                '<p class="muted">Whoever has it sees what its folders allow, until you switch '
                'it off, replace or remove it. Scripts send the part after <code>/t/</code> as '
                '<code>Authorization: Bearer …</code>. '
                f'<a href="/admin/shares?name={quote(name)}">Choose its folders</a></p></div>')
    return ((f'<div class="note">{escape(note)}</div>' if note else "")
            + (f'<div class="err">{escape(error)}</div>' if error else ""))


def _form(auth, user, action: str, name: str, inner: str, cls: str = "",
          confirm: str = "") -> str:
    onsubmit = f' onsubmit="return confirm({escape(repr(confirm))})"' if confirm else ""
    return (f'<form class="inline" method="post" action="/admin"{onsubmit}>'
            f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
            f'<input type="hidden" name="action" value="{action}">'
            f'<input type="hidden" name="name" value="{escape(name)}">{inner}</form>')


def page(auth, user, note: str = "", error: str = "", title: str = "") -> bytes:
    """The user list, for an admin."""
    by_group = bool(auth.admin_group)
    rows = []
    links = []
    for acc in auth.users.all():
        if acc.source == "link":
            links.append(acc)
            continue
        me = acc.name.lower() == user.name.lower()
        acts = []
        owner = auth.users.is_owner(acc)
        if acc.source == "guest":
            role = f'{acc.role} <span class="muted">(guest)</span>'
        elif owner:
            role = (f'{acc.role} <span class="muted" title="ADMIN_USER: always an admin">'
                    '(owner)</span>')
        elif me and acc.admin:
            role = (f'{acc.role} <span class="muted" title="Another admin can change your '
                    'role">(you)</span>')
        elif by_group and acc.source != "local":
            role = f'{acc.role} <span class="muted">(group)</span>'
        else:
            opts = "".join(f'<option{" selected" if r == acc.role else ""}>{r}</option>'
                           for r in ROLES)
            role = _form(auth, user, "role", acc.name,
                         f'<select name="role" aria-label="Role" onchange="this.form.submit()">'
                         f'{opts}</select><noscript><button>Set</button></noscript>')
        if acc.source == "local" and auth.mode == "local":
            acts.append(_form(auth, user, "password", acc.name,
                              '<input name="password" type="password" placeholder="New password" '
                              'autocomplete="new-password" aria-label="New password" required>'
                              '<button>Set password</button>'))
        rights = []
        for key, label, on, locked in (
                ("web", "Web", acc.web, acc.admin),
                ("mcp", "MCP", acc.mcp, acc.source == "guest")):
            if locked:
                rights.append(f'<span class="right{" on" if on else ""}" title="fixed">{label}</span>')
            else:
                rights.append(_form(auth, user, "rights", acc.name,
                                    f'<input type="hidden" name="{key}" value="{0 if on else 1}">'
                                    f'<button class="right{" on" if on else ""}" aria-pressed="{str(on).lower()}" '
                                    f'title="{label}: {"on – click to turn off" if on else "off – click to turn on"}">'
                                    f'{label}</button>'))
        acts.append('<span class="rights">' + "".join(rights) + "</span>")
        if not acc.admin:
            n = ("default" if acc.shares is None else
                 f"{sum(1 for x in acc.shares if x['access'] != 'none')} shared")
            acts.append(f'<a class="btn" href="/admin/shares?name={quote(acc.name)}">'
                        f'Folders <span class="muted">({n})</span></a>')
        if not me and not owner:
            acts.append(_form(auth, user, "active", acc.name,
                              f'<input type="hidden" name="on" value="{0 if acc.active else 1}">'
                              f'<button>{"Switch off" if acc.active else "Switch on"}</button>'))
            if acc.source != "guest":
                acts.append(_form(auth, user, "delete", acc.name,
                                  '<button class="danger">Remove</button>',
                                  confirm=f"Remove {acc.name}?"))
        last = escape((acc.last_login or "–").replace("T", " ").replace("+00:00", " UTC"))
        from .server import avatar_img
        rows.append(
            f'<tr class="{"" if acc.active else "off"}"><td>{avatar_img(acc.name, 24)} '
            f'<strong>{escape(acc.name)}</strong>'
            + (' <span class="muted">(you)</span>' if me else "")
            + ("" if acc.active else ' <span class="tag">off</span>')
            + f'</td><td>{role}</td><td>{escape(acc.source)}</td><td class="muted">{last}</td>'
            f'<td class="acts"><div>{"".join(acts)}</div></td></tr>')
    add = ""
    if auth.mode == "local":
        opts = "".join(f"<option>{r}</option>" for r in reversed(ROLES))
        add = ('<h2>Add a user</h2><form class="add" method="post" action="/admin">'
               f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
               '<input type="hidden" name="action" value="create">'
               '<input name="name" placeholder="User name" autocomplete="off" required aria-label="User name">'
               '<input name="password" type="password" placeholder="Password (8+ characters)" '
               'autocomplete="new-password" required aria-label="Password">'
               f'<select name="role" aria-label="Role">{opts}</select>'
               '<button class="primary">Add</button></form>')
    else:
        add = ('<p class="muted">Users log in through '
               + escape("the identity provider" if auth.mode == "oidc" else "the login proxy")
               + " and appear here after their first login."
               + (f" Members of the group {escape(auth.admin_group)!s} are admins." if by_group else "")
               + "</p>")
    from . import site
    site_form = ('<h2>Title</h2><form class="add" method="post" action="/admin">'
                 f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
                 '<input type="hidden" name="action" value="title">'
                 f'<input name="title" value="{escape(site.title())}" maxlength="{site.MAX_TITLE}" '
                 f'placeholder="{escape(site.DEFAULT_TITLE)}" aria-label="Title" style="min-width:18em">'
                 '<button class="primary">Save</button>'
                 '<button name="reset" value="1">Default</button></form>'
                 '<p class="muted">The headline of the overview and the login page. '
                 f'Default: {escape(site.DEFAULT_TITLE)} (<code>VIEWER_TITLE</code>).</p>')
    body = (_messages(note, error) + _nav("users")
            + '<h2>Users</h2><table><thead><tr><th>User</th><th>Role</th><th>Login</th>'
            '<th>Last login</th><th></th></tr></thead><tbody>' + "".join(rows)
            + "</tbody></table>" + add + _links(auth, user, links) + site_form)
    return _wrap("Users", body, user, title)


def _date(value: str | None, empty: str = "–") -> str:
    return escape((value or empty)[:16].replace("T", " "))


def _links(auth, user, links: list) -> str:
    """Access links: named accounts for the web viewer only, opened with a
    link; their folders, last day, switch, new link, remove."""
    if not getattr(auth, "links", False):
        return ""
    rows = []
    for acc in links:
        info = auth.users.link_info(acc.name) or {}
        n = ("default" if acc.shares is None else
             f"{sum(1 for x in acc.shares if x['access'] != 'none')} shared")
        state = ("" if acc.active else ' <span class="tag">off</span>') + (
            ' <span class="tag">expired</span>' if acc.expired else "")
        acts = [
            f'<a class="btn" href="/admin/shares?name={quote(acc.name)}">'
            f'Folders <span class="muted">({n})</span></a>',
            _form(auth, user, "link_expires", acc.name,
                  f'<input type="date" name="expires" value="{escape(acc.expires or "")}" '
                  'aria-label="Last day" title="The last day the link works; empty: no end">'
                  '<button title="Save the last day">Set</button>'),
            _form(auth, user, "active", acc.name,
                  f'<input type="hidden" name="on" value="{0 if acc.active else 1}">'
                  f'<button>{"Switch off" if acc.active else "Switch on"}</button>'),
            _form(auth, user, "link_new", acc.name,
                  '<button title="A new link; the old one and its sessions stop working">'
                  'New link</button>',
                  confirm=f"New link for {acc.name}? The old link stops working."),
            _form(auth, user, "delete", acc.name, '<button class="danger">Remove</button>',
                  confirm=f"Remove the access link {acc.name}?"),
        ]
        rows.append(
            f'<tr class="{"" if acc.active and not acc.expired else "off"}"><td>'
            f'<strong>{escape(acc.name)}</strong>{state}</td>'
            f'<td class="muted">{_date(acc.expires, "no end")}</td>'
            f'<td class="muted">{_date(info.get("last_used"), "never")}</td>'
            f'<td class="acts"><div>{"".join(acts)}</div></td></tr>')
    table = ('<table><thead><tr><th>Name</th><th>Last day</th><th>Last used</th><th></th>'
             '</tr></thead><tbody>' + "".join(rows) + '</tbody></table>' if rows else "")
    return ('<h2>Access links</h2><p class="muted">A link that opens the viewer without a '
            'password, with the folders you give it (read only; no MCP). New links see '
            'nothing until you choose their folders.</p>' + table
            + '<form class="add" method="post" action="/admin" style="margin-top:12px">'
            f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
            '<input type="hidden" name="action" value="link_create">'
            '<input name="name" placeholder="Name, e.g. Carpenter Meier" autocomplete="off" '
            'required aria-label="Name of the link">'
            '<input type="date" name="expires" aria-label="Last day (optional)" '
            'title="The last day the link works (optional)">'
            '<button class="primary">New access link</button></form>')


def _nav(here: str) -> str:
    """The admin panel's pages."""
    return '<nav class="sub">' + "".join(
        f'<a class="btn{" primary" if key == here else ""}" href="{href}"'
        + (' aria-current="page"' if key == here else "") + f'>{label}</a>'
        for key, href, label in (("users", "/admin", "Users"),
                                 ("renders", "/admin/renders", "Renders"),
                                 ("log", "/admin/log", "Log"))) + "</nav>"


#: The render states (viewer/render.py ``Renderer.status``) as shown.
STATES = {"rendered": "rendered", "outdated": "outdated", "rendering": "rendering now",
          "queued": "queued", "failed": "failed", "skipped": "skipped",
          "missing": "not rendered"}
KINDS = {"view": "View", "sheet": "Sheet", "glb": "3D", "pdf": "PDF"}


def _item_link(slug: str, e: dict) -> str:
    kind, _, n = e["item"].partition(":")
    q = {"view": f"?view={n}", "sheet": f"?sheet={n}", "glb": "?3d=1", "pdf": "?pdf=1"}[kind]
    path = " › ".join(e.get("folder") or [])
    name = escape(e["name"] or kind)
    return (f'<a href="/m/{quote(slug)}{q}">{name}</a>'
            + (f' <span class="muted">({escape(path)})</span>' if path else ""))


def renders_page(auth, user, models: list[dict], note: str = "", error: str = "",
                 title: str = "") -> bytes:
    """Every saved view, sheet, 3D model and PDF of every model and whether
    it is rendered (``Renderer.status``), for an admin."""
    import time as _time
    total: dict[str, int] = {}
    blocks = []
    csrf = auth.sessions.csrf(user.name)
    for m in models:
        counts: dict[str, int] = {}
        rows = []
        for e in m["items"]:
            counts[e["status"]] = counts.get(e["status"], 0) + 1
            when = ""
            if e.get("at"):
                when = _time.strftime("%Y-%m-%d %H:%M", _time.localtime(e["at"]))
                if e.get("seconds") is not None:
                    when += f" · {e['seconds']} s"
            rows.append(
                f'<tr><td>{KINDS.get(e["kind"], e["kind"])}</td><td>{_item_link(m["slug"], e)}</td>'
                f'<td><span class="st {e["status"]}">{STATES.get(e["status"], e["status"])}</span></td>'
                f'<td class="muted">{escape(when)}</td>'
                f'<td class="detail">{escape(e.get("detail", ""))}</td></tr>')
        for k, v in counts.items():
            total[k] = total.get(k, 0) + v
        done = counts.get("rendered", 0)
        problem = m["errors"] or not m["fresh"] or done < len(m["items"])
        head = (f'<strong>{escape(m["name"])}</strong> <span class="muted">{escape(m["folder"])}'
                f' / {escape(m["rel"])}</span> <span class="st {"rendered" if not problem else "queued" if m["listing"] else "missing"}">'
                f'{done} / {len(m["items"])} rendered</span>'
                + ("" if m["fresh"] else ' <span class="st outdated">model changed</span>')
                + (' <span class="st failed">failed to open</span>' if m["errors"] else "")
                + f'<form class="inline" method="post" action="/admin/renders">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                f'<input type="hidden" name="slug" value="{escape(m["slug"])}">'
                '<button name="action" value="render" title="Render everything of this model that is not rendered yet">'
                'Render missing</button></form>')
        if m["errors"]:
            table = f'<div class="err">{escape("; ".join(m["errors"]))}</div>'
        elif not m["listed"]:
            table = '<p class="muted">Not listed yet: the model was not opened so far.</p>'
        elif not rows:
            table = '<p class="muted">No saved views, sheets, 3D model or PDF.</p>'
        else:
            table = ('<table><thead><tr><th>Type</th><th>Name</th><th>Status</th>'
                     '<th>Rendered</th><th></th></tr></thead><tbody>' + "".join(rows)
                     + "</tbody></table>")
        blocks.append(f'<details class="model"{" open" if problem else ""}><summary>{head}</summary>'
                      f'{table}</details>')
    chips = "".join(f'<span class="st {k}">{total[k]} {STATES[k]}</span>'
                    for k in STATES if total.get(k))
    busy = total.get("rendering") or total.get("queued") or any(m["listing"] for m in models)
    body = (_messages(note, error) + _nav("renders")
            + f'<h2>Renders</h2><div class="chips">{chips or "<span class=muted>nothing to render</span>"}'
            f'<form class="inline" method="post" action="/admin/renders">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<button name="action" value="render-all">Render all missing</button></form>'
            '<a class="btn" href="/admin/renders">Refresh</a></div>'
            + ("".join(blocks) or '<p class="muted">No models.</p>')
            # While something renders or waits: the page refreshes itself.
            + ('<script>setTimeout(()=>{location.replace("/admin/renders")},10000)</script>' if busy else ""))
    return _wrap("Renders", body, user, title)


def act(auth, user, form: dict) -> tuple[str, str]:
    """One change from the admin panel: (what was done, or what went wrong)."""
    def get(key: str) -> str:
        return (form.get(key) or [""])[0]

    action, name = get("action"), get("name").strip()
    me = name.lower() == user.name.lower()
    users = auth.users
    try:
        if action == "title":
            from . import site
            now = site.set_title("" if get("reset") == "1" else get("title"))
            return f"The title is now {now}.", ""
        if action == "create":
            if auth.mode != "local":
                raise UserError("users of a provider or proxy appear after their first login")
            acc = users.create(name, get("password"), get("role") or "user")
            return f"Added {acc.name}.", ""
        if action == "role":
            if me and get("role") != "admin" and user.admin:
                raise UserError("you cannot take away your own admin role; "
                                "another admin can")
            acc = users.get(name)
            if acc and auth.admin_group and acc.source != "local":
                raise UserError(f"the group {auth.admin_group} decides {acc.name}'s role")
            users.set_role(name, get("role"))
            return f"{name} is now {get('role')}.", ""
        if action == "password":
            users.set_password(name, get("password"))
            return f"New password set for {name}.", ""
        if action == "active":
            if me:
                raise UserError("you cannot switch yourself off")
            on = get("on") == "1"
            users.set_active(name, on)
            return f"{name} is switched {'on' if on else 'off'}.", ""
        if action == "rights":
            web, mcp = get("web"), get("mcp")
            users.set_rights(name, web=(web == "1") if web else None,
                             mcp=(mcp == "1") if mcp else None)
            what = "web viewer" if web else "MCP server"
            return f"{name} {'may' if (web or mcp) == '1' else 'may no longer'} use the {what}.", ""
        if action == "shares":
            acc = users.get(name)
            if acc is None:
                raise UserError(f"there is no user {name!r}")
            if get("default") == "1":
                users.set_shares(name, None)
                return f"{name} has the default folders again.", ""
            chosen = []
            drop = set(form.get("del", []))       # a pattern's Delete button
            for key, vals in form.items():
                if key.startswith("s:") and vals[0] in share_mod.ACCESS and key[2:] not in drop:
                    chosen.append({"path": key[2:] or share_mod.ALL, "access": vals[0]})
            try:
                chosen += share_mod.parse(get("rules"))
            except ValueError as exc:
                raise UserError(f"in the new lines: {exc}") from None
            users.set_shares(name, chosen)
            if drop:
                return f"Pattern {', '.join(sorted(drop))} removed; folders of {name} saved.", ""
            return f"Folders of {name} saved.", ""
        if action == "link_create":
            if not getattr(auth, "links", False):
                raise UserError("access links need the local or oidc login")
            acc, token = users.create_link(name, get("expires"))
            return f"LINK:{acc.name}:{token}", ""
        if action == "link_new":
            return f"LINK:{name}:{users.new_link(name)}", ""
        if action == "link_expires":
            day = users.set_expires(name, get("expires"))
            return (f"The link {name} works through {day}." if day
                    else f"The link {name} has no end.", "")
        if action == "delete":
            if me:
                raise UserError("you cannot remove yourself")
            users.delete(name)
            return f"Removed {name}.", ""
        raise UserError("unknown action")
    except UserError as exc:
        return "", str(exc)[:1].upper() + str(exc)[1:] + "."


ACCESS_NAMES = {"": "–", "none": "No access", "r": "Read", "rw": "Read & write"}

#: Tooltips of the access choices.
ACCESS_TIPS = {
    "": "No setting here: the folder above (or a pattern) decides",
    "none": "Hide it: the user does not see these models, even if a wider share allows them",
    "r": "The user sees the models in the viewer and can open them over MCP",
    "rw": "Like Read, and over MCP the user may also save and export here "
          "(a read-only model folder stays read-only)",
}

#: The help on the folders page (the README says the same under "Users").
SHARES_HELP = """
<details class="help"><summary>How folder access works</summary>
<p>Each line below is a <em>share</em>: a folder, a single model or a pattern, with an access:
<strong>Read</strong>, <strong>Read &amp; write</strong> (also save and export over MCP) or
<strong>No access</strong>. A share covers its folder and everything inside it.</p>
<p><strong>The most specific share wins</strong>: the one that starts to cover a model at the
deepest folder level. <code>projects:r</code> with <code>projects/secret:none</code> hides
<code>projects/secret</code> and shows the rest of <code>projects</code>. On the same level a
plain folder beats a pattern, and of two patterns the one with less access wins. Without any
share the user sees nothing. Read-only model folders stay read-only. Admins see everything.</p>
<p><strong>Patterns</strong> include or exclude many folders and files at once. They are paths
from the data folder, like the folders in the tree:</p>
<table><tbody>
<tr><td><code>*</code></td><td>any name within one folder level (alone: every folder)</td></tr>
<tr><td><code>?</code></td><td>one character</td></tr>
<tr><td><code>**</code></td><td>any number of folders, also none</td></tr>
<tr><td><code>**/private:none</code></td><td>every folder named <em>private</em>, at any depth</td></tr>
<tr><td><code>projects/*/plans:r</code></td><td>the <em>plans</em> folder of each project</td></tr>
<tr><td><code>**/*.bak.igz:none</code></td><td>backup copies, wherever they are</td></tr>
<tr><td><code>archive/20??/**:r</code></td><td>everything in <em>archive/2000</em> … <em>archive/2099</em></td></tr>
</tbody></table>
<p>Example: only the public part of every project: <code>*:none</code> and
<code>projects/*/public:r</code>. <em>Check a path</em> at the bottom shows which share decides
for a folder or model.</p>
</details>
"""


def shares_page(auth, user, name: str, note: str = "", error: str = "",
                title: str = "", check: str = "") -> bytes:
    """One user's folders, for an admin: each model folder and the folders
    in it and the patterns, with what the user may do there; and a check
    of one path (which share decides)."""
    acc = auth.users.get(name)
    if acc is None:
        return _wrap("Folders", _messages("", f"There is no user {name}."), user, title)
    own = {s["path"]: s["access"] for s in (acc.shares or [])}
    using_default = acc.shares is None
    current = own if not using_default else {
        s["path"]: s["access"] for s in share_mod.defaults()}
    paths = [share_mod.ALL] + share_mod.tree()
    paths += [p for p in current if p not in paths and not share_mod.is_pattern(p)]
    patterns = [p for p in current if share_mod.is_pattern(p)]

    def select(path: str, label: str, pattern: bool = False) -> str:
        here = current.get(path, "")
        # A pattern has no "–" (nothing set): its Delete button removes it.
        opts = "".join(f'<option value="{v}" title="{escape(ACCESS_TIPS[v])}"'
                       f'{" selected" if v == here else ""}>{escape(t)}</option>'
                       for v, t in ACCESS_NAMES.items() if v or not pattern)
        tip = "What this share gives" if pattern else "What this share gives; “–” removes it"
        return (f'<select name="s:{escape(path)}" aria-label="Access to {escape(label)}" '
                f'title="{tip}">' + opts + '</select>')

    rows = []
    for path in paths:
        depth = 0 if path in (share_mod.ALL, "") else path.count("/") + 1
        label = "All folders" if path == share_mod.ALL else (path.rsplit("/", 1)[-1] or "data")
        tip = "Every folder (*)" if path == share_mod.ALL else path
        if acc.admin:
            got = "rw"
        elif path == share_mod.ALL:          # not a folder: what the share itself gives
            got = share_mod.access(share_mod.own_shares(acc), share_mod.ALL)
        else:
            got = share_mod.effective(acc, path or "*")
        rows.append(f'<tr><td style="padding-left:{10 + depth * 18}px" title="{escape(tip)}">'
                    f'{escape(label)}</td><td>{select(path, label)}</td>'
                    f'<td class="muted">{escape(ACCESS_NAMES[got])}</td></tr>')
    pattern_rows = "".join(
        f'<tr><td title="A pattern: it covers every folder and model it matches">'
        f'<code>{escape(p)}</code></td><td>{select(p, p, pattern=True)}</td>'
        f'<td><button type="submit" name="del" value="{escape(p)}" '
        f'aria-label="Delete the pattern {escape(p)}" '
        f'title="Remove this pattern (the other changes on this page are saved too)">'
        f'Delete</button></td></tr>' for p in patterns)
    csrf = auth.sessions.csrf(user.name)
    body = (_messages(note, error)
            + f'<p>What <strong>{escape(acc.name)}</strong> may see (and, through MCP, write). '
            '“–” takes what the folder above says; the most specific setting wins. '
            'Read-only model folders stay read-only.</p>'
            + SHARES_HELP
            + ('<p class="muted">Now: the default for every user (DEFAULT_SHARES). '
               'Saving below gives this user their own.</p>' if using_default else "")
            + (f'<p class="muted">{escape(acc.name)} is an admin: admins see and write '
               'everything, whatever is set here.</p>' if acc.admin else "")
            + '<form method="post" action="/admin">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="shares">'
            f'<input type="hidden" name="name" value="{escape(acc.name)}">'
            '<table><thead><tr>'
            '<th title="The model folders and the folders in them">Folder</th>'
            '<th title="The access set for this folder; “–”: nothing set here">Share</th>'
            '<th title="What the user gets in this folder itself, after every share, '
            'pattern and the model folder\'s mode">Result</th></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table>'
            + ('<h2 title="Shares that match many folders or models at once">Patterns</h2>'
               '<table><thead><tr><th>Pattern</th><th>Share</th><th></th></tr></thead><tbody>'
               + pattern_rows + '</tbody></table>' if patterns else "")
            + '<div class="add" style="margin-top:12px">'
            '<label for="rules">More shares, one per line: <code>folder-or-pattern:access</code> '
            'with <code>r</code>, <code>rw</code> or <code>none</code> (see the help above)</label>'
            '<textarea id="rules" name="rules" spellcheck="false" '
            'placeholder="projects/2026/x:rw&#10;**/private:none&#10;**/*.bak.igz:none" '
            'title="A folder (projects/2026), a model (projects/a.igz) or a pattern with *, ? '
            'or **, then : and r, rw or none. Without an access: r."></textarea>'
            '<span class="spacer"></span><button class="primary" '
            'title="Save the shares above and the new lines">Save</button></div></form>'
            + ("" if using_default else
               _form(auth, user, "shares", acc.name,
                     '<input type="hidden" name="default" value="1">'
                     '<button title="Forget this user’s own shares; DEFAULT_SHARES applies '
                     'again">Back to the default</button>'))
            + _check_form(acc, check)
            + '<p><a href="/admin">← All users</a></p>')
    return _wrap(f"Folders of {acc.name}", body, user, title)


def explain(acc, path: str) -> tuple[str, str]:
    """What ``acc`` gets on ``path`` and why, as (access, reason in HTML)."""
    got = share_mod.effective(acc, path)
    if acc.admin:
        return got, "they are an admin" + (
            ", capped by the read-only model folder" if got == "r" else "")
    wanted, rule = share_mod.decide(share_mod.own_shares(acc), path)
    if rule is None:
        why = "no share covers it"
    else:
        why = (f'of the share <code>{escape(rule["path"])}:{escape(rule["access"])}</code>'
               + (" (a pattern)" if share_mod.is_pattern(rule["path"]) else ""))
        if acc.shares is None:
            why += " from DEFAULT_SHARES"
    if got != wanted:
        folder = share_mod.folders.folder_of((share_mod.folders.DATA_DIR / path).resolve())
        why += (", capped by the read-only model folder" if folder is not None
                else ", but it is not in a model folder")
    return got, why


def _check_form(acc, check: str) -> str:
    """Check a path: what the user gets there and which share decides."""
    check = check.strip().replace("\\", "/").strip("/")
    answer = ""
    if check:
        got, why = explain(acc, check)
        answer = (f'<p class="note"><code>{escape(check)}</code>: '
                  f'<strong>{escape(ACCESS_NAMES[got])}</strong>, because {why}.</p>')
    return ('<h2 title="Which share decides for one folder or model">Check a path</h2>'
            '<form class="add" method="get" action="/admin/shares">'
            f'<input type="hidden" name="name" value="{escape(acc.name)}">'
            f'<input name="check" value="{escape(check)}" style="flex:1 1 260px" '
            'placeholder="projects/2026/house.igz" aria-label="Path to check" '
            'title="A folder or model, as a path from the data folder"> '
            '<button title="Show what the user gets there and which share decides">Check</button>'
            '</form>' + answer)


#: How the account page names the settings and their values.
LABELS = {
    "nav_mode": ("Folders in the View / 3D / Sheet dropdowns",
                 {"list": "List (every level)", "tree": "Tree (one level at a time)"}),
    "edges_3d": ("Edges in the 3D view", {True: "On", False: "Off"}),
}


def setting_value(key: str, raw: str):
    """A setting's value as a form sends it: "" is the default (None)."""
    if raw == "":
        return None
    allowed = SETTINGS.get(key, ((),))[0]
    if allowed and isinstance(allowed[0], bool):
        return raw.lower() in ("1", "true", "on", "yes")
    return raw


def _settings_form(auth, user) -> str:
    from .server import NAV_MODE
    conf = auth.settings(user)
    acc = auth.users.get(user.name)
    own = acc.config if acc else {}
    fields = []
    for key, (label, names) in LABELS.items():
        allowed, default = SETTINGS[key]
        if default is None:                    # as the container is set up
            default = NAV_MODE if key == "nav_mode" else allowed[0]
        opts = [f'<option value="">Default ({escape(names[default])})</option>']
        for v in allowed:
            sel = " selected" if key in own and conf[key] == v else ""
            value = ("1" if v else "0") if isinstance(v, bool) else v
            opts.append(f'<option value="{value}"{sel}>{escape(names[v])}</option>')
        fields.append(f'<label for="s-{key}">{escape(label)}</label>'
                      f'<select id="s-{key}" name="{key}">{"".join(opts)}</select>')
    return ('<h2>Settings</h2><form class="stack" method="post" action="/account">'
            f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
            '<input type="hidden" name="action" value="settings">' + "".join(fields)
            + '<button class="primary">Save</button></form>')


def account_page(auth, user, note: str = "", error: str = "", title: str = "") -> bytes:
    """The user's own page: who they are, their settings, and (local
    users) a new password."""
    acc = auth.users.get(user.name)
    if acc and acc.source == "guest":
        info = ('<p>Logged in as <strong>guest</strong>. Every guest shares these '
                'settings.</p>')
    elif acc and acc.source == "link":
        info = (f'<p>Logged in with the access link <strong>{escape(acc.name)}</strong>'
                + (f', valid through {escape(acc.expires)}' if acc.expires else "")
                + '. Everyone with this link shares these settings.</p>')
    else:
        info = (f'<p>Logged in as <strong>{escape(user.name)}</strong>, {escape(user.role)}'
                f'{", through " + escape(acc.source) if acc and acc.source != "local" else ""}.</p>')
    pw = ""
    if acc and acc.source == "local" and auth.mode == "local":
        pw = ('<h2>Password</h2><form class="stack" method="post" action="/account">'
              f'<input type="hidden" name="csrf" value="{auth.sessions.csrf(user.name)}">'
              '<input type="hidden" name="action" value="password">'
              '<label for="o">Current password</label><input id="o" name="old" type="password" '
              'autocomplete="current-password" required>'
              '<label for="n">New password</label><input id="n" name="password" type="password" '
              'autocomplete="new-password" required>'
              '<button class="primary">Change password</button></form>')
    settings = (_avatar_form(auth, user, acc) + _settings_form(auth, user)) if acc else ""
    return _wrap("Account", _messages(note, error) + info + settings + pw
                 + _tokens(auth, user, acc), user, title)


def _avatar_form(auth, user, acc) -> str:
    """The user's avatar: pick a style, press New until one fits."""
    from . import avatar
    from .server import avatar_img
    current = (avatar.valid(acc.avatar) or {}).get("style", "initials")
    csrf = auth.sessions.csrf(user.name)
    opts = "".join(f'<option{" selected" if st == current else ""}>{st}</option>'
                   for st in avatar.STYLES)
    shared = ' <span class="muted">(every guest sees the same)</span>' if acc.source == "guest" else ""
    return ('<h2>Avatar</h2><div class="avatar-box">' + avatar_img(acc.name, 72)
            + '<form class="inline" method="post" action="/account">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="avatar">'
            f'<select name="style" aria-label="Style">{opts}</select>'
            '<button class="primary">New</button></form>'
            + ("" if acc.avatar is None else
               '<form class="inline" method="post" action="/account">'
               f'<input type="hidden" name="csrf" value="{csrf}">'
               '<input type="hidden" name="action" value="avatar_reset">'
               '<button>Default</button></form>')
            + shared + '</div>')


def _tokens(auth, user, acc) -> str:
    """Personal MCP access tokens, for users who may use the MCP server."""
    if acc is None or not acc.mcp:
        return ""
    csrf = auth.sessions.csrf(user.name)
    rows = "".join(
        f'<tr><td>{escape(t["label"] or "–")}</td>'
        f'<td class="muted">{escape(t["created"][:10])}</td>'
        f'<td class="muted">{escape((t["last_used"] or "never")[:16].replace("T", " "))}</td>'
        '<td class="acts"><div><form class="inline" method="post" action="/account">'
        f'<input type="hidden" name="csrf" value="{csrf}">'
        '<input type="hidden" name="action" value="revoke">'
        f'<input type="hidden" name="id" value="{t["id"]}">'
        '<button class="danger">Revoke</button></form></div></td></tr>'
        for t in auth.users.tokens(acc.name))
    table = ('<table><thead><tr><th>Name</th><th>Made</th><th>Last used</th><th></th></tr></thead>'
             f'<tbody>{rows}</tbody></table>' if rows else "")
    return ('<h2>MCP access</h2><p class="muted">A personal token for an MCP client '
            '(<code>Authorization: Bearer &lt;token&gt;</code> with MCP_AUTH=token). The client '
            'sees the folders you see here; with read &amp; write it may save and export.</p>'
            + table
            + '<form class="add" method="post" action="/account" style="margin-top:12px">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            '<input type="hidden" name="action" value="token">'
            '<input name="label" placeholder="Name, e.g. Claude Desktop" aria-label="Token name">'
            '<button class="primary">New token</button></form>')


def act_account(auth, user, form: dict) -> tuple[str, str]:
    def get(key: str) -> str:
        return (form.get(key) or [""])[0]

    try:
        if get("action") == "settings":
            auth.users.set_settings(user.name, {k: setting_value(k, get(k)) for k in LABELS
                                                if k in form})
            return "Your settings are saved.", ""
        if get("action") == "avatar":
            from . import avatar
            auth.users.set_avatar(user.name, avatar.fresh(get("style")))
            return "A new avatar. Press New again for another.", ""
        if get("action") == "avatar_reset":
            auth.users.set_avatar(user.name, None)
            return "Back to the default avatar.", ""
        if get("action") == "token":
            token = auth.users.create_token(user.name, get("label"))
            return "TOKEN:" + token, ""
        if get("action") == "revoke":
            if not auth.users.revoke_token(user.name, get("id")):
                raise UserError("no such token")
            return "The token is revoked.", ""
        if get("action") == "password":
            if auth.users.authenticate(user.name, get("old")) is None:
                raise UserError("the current password is wrong")
            auth.users.set_password(user.name, get("password"))
            return "Your password is changed.", ""
        raise UserError("unknown action")
    except UserError as exc:
        return "", str(exc)[:1].upper() + str(exc)[1:] + "."


#: The log's kinds (viewer/audit.py) as the filter names them.
LOG_KINDS = {"": "Everything", "access": "Access", "login": "Logins", "logout": "Logouts",
             "admin": "Admin changes", "error": "Errors"}
#: One entry's kind, as the table names it.
LOG_KIND = {"access": "Access", "login": "Login", "logout": "Logout", "admin": "Admin",
            "error": "Error"}
LOG_PAGE = 200


def _log_filter(query: dict) -> dict:
    def get(key: str) -> str:
        return (query.get(key) or [""])[0].strip()
    kind = get("kind") if get("kind") in LOG_KINDS else ""
    since = get("since")
    since = since if len(since) == 10 and since[4] == "-" and since[7] == "-" else ""
    try:
        offset = max(0, int(get("offset") or 0))
    except ValueError:
        offset = 0
    return {"kind": kind, "user": get("user")[:64], "text": get("q")[:200],
            "since": since, "offset": offset}


def log_download(query: dict) -> bytes:
    """``/admin/log.jsonl``: what the filter finds, newest first, as JSON lines."""
    f = _log_filter(query)
    rows, _ = audit.read(f["kind"], f["user"], f["text"], f["since"], 0, 100000)
    return "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in rows).encode("utf-8")


def log_page(auth, user, query: dict, title: str = "") -> bytes:
    """``/admin/log``: the audit log (viewer/audit.py), newest first, with
    a filter by kind, user, text and first day; 200 entries a page."""
    from urllib.parse import urlencode
    f = _log_filter(query)
    rows, more = audit.read(f["kind"], f["user"], f["text"], f["since"],
                            f["offset"], LOG_PAGE)
    page_q = {k: v for k, v in (("kind", f["kind"]), ("user", f["user"]),
                                ("q", f["text"]), ("since", f["since"])) if v}
    kinds = "".join(f'<option value="{k}"{" selected" if k == f["kind"] else ""}>{v}</option>'
                    for k, v in LOG_KINDS.items())
    names = audit.users()
    if f["user"] and f["user"] not in names:
        names.append(f["user"])
    people = '<option value="">Every user</option>' + "".join(
        f'<option{" selected" if n == f["user"] else ""}>{escape(n)}</option>' for n in names)
    form = ('<form class="filters" method="get" action="/admin/log">'
            f'<select name="kind" aria-label="Kind">{kinds}</select>'
            f'<select name="user" aria-label="User">{people}</select>'
            f'<input name="q" value="{escape(f["text"])}" placeholder="Search (path, IP, text)" '
            'aria-label="Search">'
            f'<input type="date" name="since" value="{escape(f["since"])}" aria-label="From day" '
            'title="From this day on (UTC)">'
            '<button class="primary">Filter</button>'
            '<a class="btn" href="/admin/log">Reset</a>'
            f'<a class="btn" href="/admin/log.jsonl?{escape(urlencode(page_q))}" '
            'title="What the filter finds, as JSON lines">Download</a></form>')
    out = []
    for e in rows:
        kind = str(e.get("kind", ""))
        status = e.get("status")
        bad = isinstance(status, int) and status >= 400
        req = " ".join(str(e[k]) for k in ("method", "path") if e.get(k))
        if e.get("action"):
            req = (req + " · " if req else "") + str(e["action"]) + (
                f' → {e["target"]}' if e.get("target") else "")
        ip = str(e.get("ip", ""))
        if e.get("fwd"):
            ip += f' (fwd {e["fwd"]})'
        who = str(e.get("user", ""))
        if who and e.get("source"):
            who_html = (f'<a href="/admin/log?{escape(urlencode({"user": who}))}">{escape(who)}</a>'
                        f' <span class="muted">{escape(str(e["source"]))}</span>')
        elif who:
            who_html = escape(who)
        else:
            who_html = '<span class="muted">–</span>'
        ms = f' <span class="muted">{e["ms"]} ms</span>' if e.get("ms") is not None else ""
        code = ("" if status is None else
                f'<span class="st{" bad" if bad else ""}">{escape(str(status))}</span>')
        out.append(
            f'<tr><td class="when muted" data-ts="{escape(str(e.get("ts", "")))}">'
            f'{escape(str(e.get("ts", ""))[:19].replace("T", " "))} UTC</td>'
            f'<td><span class="st {escape(kind)}">{escape(LOG_KIND.get(kind, kind))}</span></td>'
            f'<td>{who_html}</td><td class="muted">{escape(ip)}</td>'
            f'<td class="req">{escape(req)}</td>'
            f'<td class="when">{code}{ms}</td>'
            f'<td class="detail">{escape(str(e.get("detail", "")))}</td></tr>')
    pager = []
    if f["offset"]:
        pager.append(f'<a class="btn" href="/admin/log?{escape(urlencode({**page_q, "offset": max(0, f["offset"] - LOG_PAGE)}))}">‹ Newer</a>')
    if more:
        pager.append(f'<a class="btn" href="/admin/log?{escape(urlencode({**page_q, "offset": f["offset"] + LOG_PAGE}))}">Older ›</a>')
    if not audit.enabled():
        info = '<p class="err">The audit log is off (<code>VIEWER_AUDIT=false</code>).</p>'
    else:
        limit = audit.days()
        info = ('<p class="muted">Who opened what, logins, changes in this panel and errors. '
                f'Kept {"for " + str(limit) + " days" if limit else "without a time limit"}, '
                f'at most {audit.keep() + 1} files of {audit.max_bytes() // 1048576} MB '
                f'(<code>{escape(str(audit.path()))}</code>). Times in your browser\'s time zone.</p>')
    table = ('<table><thead><tr><th>Time</th><th>Kind</th><th>User</th><th>Address</th>'
             '<th>Request / change</th><th>Status</th><th>Detail</th></tr></thead><tbody>'
             + "".join(out) + "</tbody></table>" if out else '<p class="muted">No entries.</p>')
    # The UTC times in the browser's time zone.
    script = ('<script>document.querySelectorAll("td.when[data-ts]").forEach(td=>{'
              'const d=new Date(td.dataset.ts);if(!isNaN(d))td.textContent=d.toLocaleString('
              'undefined,{year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",'
              'minute:"2-digit",second:"2-digit"});});</script>')
    body = (_nav("log") + "<h2>Log</h2>" + info + form + table
            + (f'<div class="chips">{"".join(pager)}</div>' if pager else "") + script)
    return _wrap("Log", body, user, title)
