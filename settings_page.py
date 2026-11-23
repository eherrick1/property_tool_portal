"""Settings tab for the portal admin console.

Lets a signed-in admin, with no developer or Google Cloud access:
  - change who each tool emails (approver, copy lists, incident carrier)
  - switch sending from Outlook to the email service, and set its from-address
  - send a test email from each tool through its real sending path
  - change the portal admin password

Values are written to the shared Firestore document the tools read (see
shared_settings.py). Every save and password change is logged to the
property_tools_audit collection. Test emails are sent by the tools themselves:
the portal calls each tool's /settings/test-email endpoint with that tool's
admin token, so a green result means that tool can really send.
"""
import hmac
import json
import re
import secrets
import time
import urllib.error
import urllib.request

from flask import abort, flash, get_flashed_messages, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import shared_settings

AUTH_DOC = "portal_auth"
AUDIT_COLLECTION = "property_tools_audit"
MIN_PASSWORD = 10
_ADDR_RE = re.compile(r"^[^@\s,;:<>\"]+@[^@\s,;:<>\"]+\.[^@\s,;:<>\"]+$")

# (section, key, label, kind) in page order. kind: "email", "text", "list".
FIELDS = {
    "capital": [
        ("approver_name", "Approver name (also printed on signed approvals)", "text"),
        ("approver_email", "Approver email (gets review requests)", "email"),
        ("approval_copies", "Copy approved requests to", "list"),
    ],
    "expense": [
        ("approver_name", "Approver name", "text"),
        ("approver_email", "Approver email (gets review requests)", "email"),
        ("review_cc", "Copy review requests to", "list"),
        ("approved_copies", "Copy approved reports to", "list"),
    ],
    "incident": [
        ("approver_name", "Reviewer name", "text"),
        ("approver_email", "Reviewer email (gets new reports)", "email"),
        ("cc", "Copy every incident email to", "list"),
        ("carrier_email", "Carrier address (\"Send to Broadspire\" button)", "email"),
    ],
}
TOOL_TITLES = {"capital": "Capital Authorizations", "expense": "Expense Reports",
               "incident": "Incident Reports"}


# --- Storage ---------------------------------------------------------------

def _doc(name):
    return shared_settings._db().collection(shared_settings.COLLECTION).document(name)


def _audit(action, detail):
    try:
        shared_settings._db().collection(AUDIT_COLLECTION).add({
            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "action": action, "detail": detail,
            "ip": (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                   or request.remote_addr)})
    except Exception as e:
        print(f"[settings] audit write failed: {type(e).__name__}")


def check_password(supplied, env_password):
    """Portal sign-in. A password changed on this page lives (hashed) in
    Firestore and replaces the env one. If Firestore can't be read we refuse
    rather than fall back, so an old env password never works again after a
    change."""
    if not shared_settings._firestore_enabled():
        return bool(env_password) and hmac.compare_digest(supplied, env_password)
    try:
        snap = _doc(AUTH_DOC).get()
    except Exception as e:
        print(f"[settings] could not read portal password ({type(e).__name__})")
        return False
    if snap.exists and (snap.to_dict() or {}).get("hash"):
        return check_password_hash(snap.to_dict()["hash"], supplied)
    return bool(env_password) and hmac.compare_digest(supplied, env_password)


# --- Talking to the tools ----------------------------------------------------

def _call_tool(tool, path, payload=None):
    """GET (payload None) or POST JSON to a tool, authenticated by its admin
    token. Returns (dict, error_text)."""
    if not tool["token"]:
        return None, "the portal has no admin token for this tool"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        tool["base"] + path, data=data, method="POST" if data else "GET",
        headers={"X-Admin-Token": tool["token"], "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return body, body.get("error") or f"HTTP {e.code}"
        except Exception:
            return None, f"HTTP {e.code} (the tool may need its settings update deployed)"
    except Exception as e:
        return None, f"could not reach the tool ({type(e).__name__})"


# --- Form helpers ------------------------------------------------------------

def _csrf_token():
    if "settings_csrf" not in session:
        session["settings_csrf"] = secrets.token_urlsafe(24)
    return session["settings_csrf"]


def _check_csrf():
    supplied = request.form.get("csrf", "")
    if not supplied or not hmac.compare_digest(supplied, session.get("settings_csrf", "")):
        abort(400, "This form expired. Go back, reload the page and try again.")


def _split_list(text):
    parts = re.split(r"[,;\s]+", text or "")
    return list(dict.fromkeys(p.strip() for p in parts if p.strip()))


def _display(value):
    if isinstance(value, list):
        return ", ".join(value)
    return value or ""


# --- Page --------------------------------------------------------------------

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Settings &middot; {{ company }}</title><style>{{ style|safe }}
.wrap { max-width:760px; }
section.card { background:#fff; border:1px solid #d8dee6; border-radius:6px;
               padding:1.2rem 1.3rem; margin-bottom:1.1rem; }
section.card h2 { font-size:1.02rem; margin:0 0 .2rem; color:#1f4e79; }
section.card p.hint { margin:.1rem 0 .9rem; font-size:.85rem; color:#5b6b7b; }
.field { margin-bottom:.85rem; }
.field label { display:block; font-size:.83rem; font-weight:600; margin-bottom:.25rem; }
.field input[type=text], .field input[type=email], .field input[type=password], .field textarea {
  width:100%; font:inherit; padding:.45rem .55rem; border:1px solid #c5ced8; border-radius:4px; }
.field textarea { min-height:2.6rem; resize:vertical; }
.field .now { font-size:.78rem; color:#7a8794; margin-top:.2rem; }
.radio label { font-weight:400; display:block; margin:.2rem 0; }
button.primary { font:inherit; padding:.5rem 1.2rem; border:0; border-radius:4px;
                 background:#1f4e79; color:#fff; cursor:pointer; }
button.secondary { font:inherit; padding:.4rem .9rem; border:1px solid #1f4e79; border-radius:4px;
                   background:#fff; color:#1f4e79; cursor:pointer; }
.msg { padding:.7rem .9rem; border-radius:5px; margin-bottom:1rem; font-size:.9rem; }
.msg.ok { background:#e8f4ea; color:#1d5b2a; border:1px solid #b9dcbf; }
.msg.err { background:#fbeaea; color:#7d2020; border:1px solid #eac0c0; }
.testrow { display:flex; gap:.6rem; align-items:center; flex-wrap:wrap; margin-bottom:.5rem; }
.testrow span { min-width:12rem; font-size:.9rem; }
.status { font-size:.85rem; color:#5b6b7b; margin:.2rem 0 .8rem; }
.warn { color:#8a5a00; }
</style></head>
<body>
<div class="topbar"><b>{{ company }}</b><span>Settings</span></div>
<div class="wrap">
  <h1>Settings</h1>
  {% for cat, text in messages %}<div class="msg {{ 'ok' if cat == 'ok' else 'err' }}">{{ text }}</div>{% endfor %}

  <form method="post" action="{{ url_for('settings_save') }}">
    <input type="hidden" name="csrf" value="{{ csrf }}">

    <section class="card">
      <h2>How emails are sent</h2>
      <p class="hint">Outlook uses the mailbox login set on each tool. The email service sends
        from a company address with no mailbox or password; it needs its one-time setup
        (see the handover note) before it will work. If it is chosen but not set up, the tools
        keep using Outlook.</p>
      <div class="field radio">
        <label><input type="radio" name="send_via" value="outlook" {{ 'checked' if send_via != 'service' }}> Outlook (current mailbox login)</label>
        <label><input type="radio" name="send_via" value="service" {{ 'checked' if send_via == 'service' }}> Email service</label>
      </div>
      <div class="field"><label for="from_address">Send from (email service)</label>
        <input type="email" id="from_address" name="from_address" value="{{ email.from_address or '' }}" placeholder="noreply@wrightinvestments.com"></div>
      <div class="field"><label for="from_name">Sender name</label>
        <input type="text" id="from_name" name="from_name" value="{{ email.from_name or '' }}" placeholder="Wright Property Tools"></div>
      <div class="field"><label for="reply_to">Replies go to (optional)</label>
        <input type="email" id="reply_to" name="reply_to" value="{{ email.reply_to or '' }}"></div>
    </section>

    {% for key, fields in field_spec.items() %}
    <section class="card">
      <h2>{{ titles[key] }}</h2>
      {% if effective[key] %}<p class="status">Sending through: {{ effective[key].sending or 'unknown' }}</p>
      {% else %}<p class="status warn">Couldn't read this tool's current settings: {{ errors[key] }}</p>{% endif %}
      {% for name, label, kind in fields %}
      <div class="field"><label for="{{ key }}__{{ name }}">{{ label }}</label>
        {% if kind == 'list' %}
        <textarea id="{{ key }}__{{ name }}" name="{{ key }}__{{ name }}" placeholder="One or more addresses, separated by commas">{{ values[key][name] }}</textarea>
        <div class="now">Leave empty to send no copies.</div>
        {% else %}
        <input type="{{ 'email' if kind == 'email' else 'text' }}" id="{{ key }}__{{ name }}" name="{{ key }}__{{ name }}" value="{{ values[key][name] }}">
        {% endif %}
      </div>
      {% endfor %}
      {% if key == 'capital' %}<p class="hint">The signature image on approved PDFs is set separately on the Capital tool.</p>{% endif %}
    </section>
    {% endfor %}

    <button class="primary" type="submit">Save settings</button>
  </form>

  <section class="card" style="margin-top:1.4rem">
    <h2>Send a test email</h2>
    <p class="hint">Each tool sends the test itself, the same way it sends real emails. Allow up to a
      minute after saving for the tools to pick up new settings.</p>
    {% for key in field_spec %}
    <form class="testrow" method="post" action="{{ url_for('settings_test') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="tool" value="{{ key }}">
      <span>{{ titles[key] }}</span>
      <input type="email" name="to" required placeholder="send to…" style="flex:1;min-width:12rem;font:inherit;padding:.4rem .5rem;border:1px solid #c5ced8;border-radius:4px">
      <button class="secondary" type="submit">Send test</button>
    </form>
    {% endfor %}
  </section>

  <section class="card">
    <h2>Change the admin password</h2>
    <p class="hint">This is the password for this admin console. At least {{ min_pw }} characters.</p>
    <form method="post" action="{{ url_for('settings_password') }}">
      <input type="hidden" name="csrf" value="{{ csrf }}">
      <div class="field"><label for="current">Current password</label>
        <input type="password" id="current" name="current" autocomplete="current-password" required></div>
      <div class="field"><label for="new">New password</label>
        <input type="password" id="new" name="new" autocomplete="new-password" required></div>
      <div class="field"><label for="confirm">New password again</label>
        <input type="password" id="confirm" name="confirm" autocomplete="new-password" required></div>
      <button class="primary" type="submit">Change password</button>
    </form>
  </section>

  <footer><a href="{{ url_for('admin') }}">Back to dashboards</a> &middot; <a href="{{ url_for('admin_logout') }}">Sign out</a></footer>
</div></body></html>"""


def init_app(app, *, style, company, tools, env_password):
    """Register the Settings routes. `tools` maps capital/expense/incident to
    {"base": url, "token": admin token}."""

    def _require_admin():
        if not session.get("portal_admin"):
            return redirect(url_for("admin"))
        return None

    @app.get("/admin/settings")
    def settings():
        if (r := _require_admin()):
            return r
        doc = shared_settings.load(force=True)
        effective, errors, values = {}, {}, {}
        for key in FIELDS:
            eff, err = _call_tool(tools[key], "/settings/effective")
            effective[key], errors[key] = eff, err
            saved = doc.get(key) or {}
            values[key] = {name: _display(saved[name] if name in saved else (eff or {}).get(name))
                           for name, _label, _kind in FIELDS[key]}
        email = doc.get("email") or {}
        return render_template_string(
            PAGE, company=company, style=style, csrf=_csrf_token(), email=email,
            send_via=email.get("send_via", "outlook"), field_spec=FIELDS, titles=TOOL_TITLES,
            values=values, effective=effective, errors=errors, min_pw=MIN_PASSWORD,
            messages=get_flashed_messages(with_categories=True))

    @app.post("/admin/settings")
    def settings_save():
        if (r := _require_admin()):
            return r
        _check_csrf()
        f = request.form
        problems = []
        email = {"send_via": "service" if f.get("send_via") == "service" else "outlook",
                 "from_address": f.get("from_address", "").strip(),
                 "from_name": f.get("from_name", "").strip(),
                 "reply_to": f.get("reply_to", "").strip()}
        for name in ("from_address", "reply_to"):
            if email[name] and not _ADDR_RE.match(email[name]):
                problems.append(f"'{email[name]}' isn't a valid email address.")
        if email["send_via"] == "service" and not email["from_address"]:
            problems.append("Choose a 'Send from' address to use the email service.")
        new_doc = {"email": email}
        for key, fields in FIELDS.items():
            section = {}
            for name, label, kind in fields:
                raw = f.get(f"{key}__{name}", "")
                if kind == "list":
                    addrs = _split_list(raw)
                    bad = [a for a in addrs if not _ADDR_RE.match(a)]
                    if bad:
                        problems.append(f"{TOOL_TITLES[key]}: '{', '.join(bad)}' isn't a valid email address.")
                    section[name] = addrs
                else:
                    value = raw.strip()
                    if kind == "email" and value and not _ADDR_RE.match(value):
                        problems.append(f"{TOOL_TITLES[key]}: '{value}' isn't a valid email address.")
                    if name.startswith("approver") and not value:
                        problems.append(f"{TOOL_TITLES[key]}: {label.split(' (')[0]} can't be empty.")
                    section[name] = value
            new_doc[key] = section
        if problems:
            for p in problems:
                flash(p, "err")
            flash("Nothing was saved.", "err")
            return redirect(url_for("settings"))
        before = shared_settings.load(force=True)
        try:
            _doc(shared_settings.SETTINGS_DOC).set(new_doc)
        except Exception as e:
            flash(f"Couldn't save ({type(e).__name__}). Nothing changed.", "err")
            return redirect(url_for("settings"))
        changed = sorted(f"{s}.{k}" for s in new_doc for k in new_doc[s]
                         if (before.get(s) or {}).get(k) != new_doc[s][k])
        _audit("settings_saved", {"changed": changed, "values": new_doc})
        shared_settings.load(force=True)
        flash("Saved. The tools pick up the new settings within a minute." if changed
              else "Saved (no changes).", "ok")
        return redirect(url_for("settings"))

    @app.post("/admin/settings/test")
    def settings_test():
        if (r := _require_admin()):
            return r
        _check_csrf()
        key, to = request.form.get("tool", ""), request.form.get("to", "").strip()
        if key not in FIELDS or not _ADDR_RE.match(to):
            flash("Enter a valid address for the test email.", "err")
            return redirect(url_for("settings"))
        result, err = _call_tool(tools[key], "/settings/test-email", {"to": to})
        if result and result.get("ok"):
            flash(f"{TOOL_TITLES[key]}: test email sent to {to} via {result.get('via')}. "
                  "Check that inbox (and spam).", "ok")
        else:
            flash(f"{TOOL_TITLES[key]}: test email failed: {err or (result or {}).get('error')}", "err")
        _audit("test_email", {"tool": key, "ok": bool(result and result.get("ok"))})
        return redirect(url_for("settings"))

    @app.post("/admin/settings/password")
    def settings_password():
        if (r := _require_admin()):
            return r
        _check_csrf()
        current, new, confirm = (request.form.get(k, "") for k in ("current", "new", "confirm"))
        if not check_password(current, env_password):
            flash("Current password is wrong. Password not changed.", "err")
        elif new != confirm:
            flash("The two new passwords don't match. Password not changed.", "err")
        elif len(new) < MIN_PASSWORD:
            flash(f"New password must be at least {MIN_PASSWORD} characters.", "err")
        else:
            try:
                _doc(AUTH_DOC).set({"hash": generate_password_hash(new),
                                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
                _audit("password_changed", {})
                flash("Password changed. Use the new password next time you sign in.", "ok")
            except Exception as e:
                flash(f"Couldn't save the new password ({type(e).__name__}). Not changed.", "err")
        return redirect(url_for("settings"))
