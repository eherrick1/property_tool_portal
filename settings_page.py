"""Settings tab for the portal admin console.

Lets a signed-in admin, with no developer or Google Cloud access:
  - change who each tool emails (approver, copy lists, incident carrier)
  - switch sending from Outlook to the email service, and set its from-address
  - send a test email from each tool through its real sending path
  - change the portal admin password
  - upload the approver's signature for Capital and Expense approvals
  - set the home-page contact and who handles password resets

Forgot password: anyone can ask for a reset from the sign-in page. The admin
(admin_email) is emailed a link to approve it; once approved, the reset address
(reset_email) is emailed a one-time link to set a new password. Both addresses
come from the saved settings, never from the request, and the emails are
relayed through the Capital tool's sending path.

Values are written to the shared Firestore document the tools read (see
shared_settings.py). Every save and password change is logged to the
property_tools_audit collection. Test emails are sent by the tools themselves:
the portal calls each tool's /settings/test-email endpoint with that tool's
admin token, so a green result means that tool can really send.
"""
import hmac
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request

from flask import abort, flash, get_flashed_messages, redirect, render_template_string, request, session, url_for
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

import shared_settings

AUTH_DOC = "portal_auth"
RESET_DOC = "portal_reset"
AUDIT_COLLECTION = "property_tools_audit"
MIN_PASSWORD = 10
RESET_LINK_SECONDS = 24 * 3600
RESET_REQUEST_GAP = 15 * 60
SIGNED_TOOLS = ("capital", "expense")
MAX_SIGNATURE_BYTES = 500_000
PORTAL_FIELDS = [
    ("contact_name", "Contact shown on the home page (\"Questions: ...\")", "text"),
    ("admin_email", "Admin: approves password resets", "email"),
    ("reset_email", "Reset link goes to (the main user)", "email"),
]
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


def _signature_info(tool, doc, approver_name):
    """What the Signatures card shows for one tool."""
    info = {"image": None, "name": "", "current": False,
            "legacy": "signature" not in (doc.get(tool) or {})}
    if (doc.get(tool) or {}).get("signature") != "uploaded":
        return info
    try:
        snap = _doc(f"signature_{tool}").get()
        sig = snap.to_dict() if snap.exists else None
    except Exception:
        sig = None
    if sig and sig.get("data"):
        import base64
        info.update(image=f"data:{sig.get('content_type', 'image/png')};base64,"
                          + base64.b64encode(bytes(sig["data"])).decode(),
                    name=sig.get("approver_name", ""),
                    current=sig.get("approver_name") == approver_name)
    return info


def _image_type(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    return None


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

    <section class="card">
      <h2>Portal</h2>
      <p class="hint">Password resets: the admin approves each request by email, then the reset
        link goes to the main user. Both must be filled in for "Forgot password?" to work.</p>
      {% for name, label, kind in portal_fields %}
      <div class="field"><label for="portal__{{ name }}">{{ label }}</label>
        <input type="{{ 'email' if kind == 'email' else 'text' }}" id="portal__{{ name }}" name="portal__{{ name }}" value="{{ portal[name] or '' }}"></div>
      {% endfor %}
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
    </section>
    {% endfor %}

    <button class="primary" type="submit">Save settings</button>
  </form>

  <section class="card" style="margin-top:1.4rem">
    <h2>Approval signatures</h2>
    <p class="hint">Stamped on signed Capital and Expense approvals. A signature belongs to the
      approver it was uploaded for: if the approver changes, approvals show the typed name until a
      new signature is uploaded. PNG or JPG, under 500 KB, ideally dark ink on a white or clear background.</p>
    {% for key in signed_tools %}
    <div style="border-top:1px solid #e3e8ee;padding-top:.8rem;margin-top:.8rem">
      <b>{{ titles[key] }}</b>
      {% if signatures[key].image %}
        <p class="status">Uploaded for {{ signatures[key].name }}{% if not signatures[key].current %} <span class="warn">(not the current approver, so it isn't being used)</span>{% endif %}</p>
        <img src="{{ signatures[key].image }}" alt="signature" style="max-width:220px;max-height:80px;background:#fff;border:1px solid #e3e8ee;padding:4px">
      {% else %}
        <p class="status">No signature: approvals show the typed name{% if signatures[key].legacy %} (or the tool's original signature file, until settings are first saved){% endif %}.</p>
      {% endif %}
      <form method="post" action="{{ url_for('settings_signature') }}" enctype="multipart/form-data" class="testrow" style="margin-top:.5rem">
        <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="tool" value="{{ key }}">
        <input type="file" name="image" accept="image/png,image/jpeg" required>
        <button class="secondary" type="submit" name="action" value="upload">Upload for {{ values[key].approver_name or 'approver' }}</button>
      </form>
      {% if signatures[key].image %}
      <form method="post" action="{{ url_for('settings_signature') }}" style="margin-top:.3rem">
        <input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="tool" value="{{ key }}">
        <button class="secondary" type="submit" name="action" value="remove">Remove signature</button>
      </form>
      {% endif %}
    </div>
    {% endfor %}
  </section>

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
        signatures = {key: _signature_info(key, doc, values[key]["approver_name"])
                      for key in SIGNED_TOOLS}
        return render_template_string(
            PAGE, company=company, style=style, csrf=_csrf_token(), email=email,
            send_via=email.get("send_via", "outlook"), field_spec=FIELDS, titles=TOOL_TITLES,
            values=values, effective=effective, errors=errors, min_pw=MIN_PASSWORD,
            portal=doc.get("portal") or {}, portal_fields=PORTAL_FIELDS,
            signed_tools=SIGNED_TOOLS, signatures=signatures,
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
        portal = {name: f.get(f"portal__{name}", "").strip() for name, _l, _k in PORTAL_FIELDS}
        for name, label, kind in PORTAL_FIELDS:
            if kind == "email" and portal[name] and not _ADDR_RE.match(portal[name]):
                problems.append(f"Portal: '{portal[name]}' isn't a valid email address.")
        new_doc["portal"] = portal
        before = shared_settings.load(force=True)
        for key in SIGNED_TOOLS:
            # Once settings are saved, the tool's original signature file is no
            # longer used: either a signature uploaded here, or the typed name.
            uploaded = (before.get(key) or {}).get("signature") == "uploaded"
            new_doc[key]["signature"] = "uploaded" if uploaded else "none"
        if problems:
            for p in problems:
                flash(p, "err")
            flash("Nothing was saved.", "err")
            return redirect(url_for("settings"))
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

    @app.post("/admin/settings/signature")
    def settings_signature():
        if (r := _require_admin()):
            return r
        _check_csrf()
        key = request.form.get("tool", "")
        if key not in SIGNED_TOOLS:
            abort(400)
        settings_ref = _doc(shared_settings.SETTINGS_DOC)
        if request.form.get("action") == "remove":
            settings_ref.set({key: {"signature": "none"}}, merge=True)
            _doc(f"signature_{key}").set({"data": None, "removed_at": _now()})
            _audit("signature_removed", {"tool": key})
            shared_settings.load(force=True)
            flash(f"{TOOL_TITLES[key]}: signature removed. Approvals show the typed name.", "ok")
            return redirect(url_for("settings"))
        upload = request.files.get("image")
        data = upload.read(MAX_SIGNATURE_BYTES + 1) if upload else b""
        kind = _image_type(data)
        if not data or not kind:
            flash("Choose a PNG or JPG image of the signature.", "err")
        elif len(data) > MAX_SIGNATURE_BYTES:
            flash("That image is over 500 KB. Crop it or save it smaller and try again.", "err")
        else:
            doc = shared_settings.load(force=True)
            name = (doc.get(key) or {}).get("approver_name")
            if not name:
                eff, _err = _call_tool(tools[key], "/settings/effective")
                name = (eff or {}).get("approver_name", "")
            _doc(f"signature_{key}").set({"data": data, "content_type": kind,
                                          "approver_name": name, "updated_at": _now()})
            settings_ref.set({key: {"signature": "uploaded"}}, merge=True)
            _audit("signature_uploaded", {"tool": key, "approver_name": name})
            shared_settings.load(force=True)
            flash(f"{TOOL_TITLES[key]}: signature uploaded for {name}. "
                  "New approvals use it within a minute.", "ok")
        return redirect(url_for("settings"))

    # --- Forgot password ------------------------------------------------------

    signer = URLSafeTimedSerializer(app.secret_key)

    def _base_url():
        # Cloud Run terminates TLS in front of the app, so request.scheme is http.
        if os.environ.get("K_SERVICE"):
            return "https://" + request.host
        return request.host_url.rstrip("/")

    def _relay(to, subject, html):
        result, err = _call_tool(tools["capital"], "/settings/send-admin-email",
                                 {"to": to, "subject": subject, "html": html})
        return bool(result and result.get("ok")), err or (result or {}).get("error")

    def _reset_request(token, salt):
        """The reset request this signed link belongs to, or None."""
        try:
            req_id = signer.loads(token, salt=salt, max_age=RESET_LINK_SECONDS)
        except (BadSignature, SignatureExpired):
            return None
        try:
            snap = _doc(RESET_DOC).get()
        except Exception:
            return None
        doc = snap.to_dict() if snap.exists else None
        return doc if doc and doc.get("id") == req_id else None

    def _simple(title, body, form=None):
        return render_template_string(
            RESET_PAGE, company=company, style=style, title=title, body=body,
            form=form, csrf=_csrf_token(), min_pw=MIN_PASSWORD,
            messages=get_flashed_messages(with_categories=True))

    @app.route("/admin/forgot", methods=["GET", "POST"])
    def admin_forgot():
        if request.method == "GET":
            return _simple("Forgot the admin password?",
                           "Press the button to ask the admin to approve a reset. Once they "
                           "approve, a link to set a new password is emailed to the main user.",
                           form="request")
        _check_csrf()
        portal = shared_settings.load(force=True).get("portal") or {}
        admin, user = portal.get("admin_email"), portal.get("reset_email")
        if not (admin and user):
            return _simple("Reset isn't set up",
                           "No admin or reset address has been saved on the Settings page yet. "
                           "Contact whoever manages these tools.")
        try:
            last = (_doc(RESET_DOC).get().to_dict() or {}).get("requested_epoch", 0)
        except Exception:
            last = 0
        if time.time() - last < RESET_REQUEST_GAP:
            return _simple("Request already sent",
                           "A reset was requested in the last 15 minutes and is waiting for the "
                           "admin's approval. Check with them before asking again.")
        req_id = secrets.token_urlsafe(16)
        _doc(RESET_DOC).set({"id": req_id, "status": "pending", "requested_at": _now(),
                             "requested_epoch": time.time(),
                             "ip": request.headers.get("X-Forwarded-For", "").split(",")[0].strip()})
        token = signer.dumps(req_id, salt="reset-approve")
        link = _base_url() + url_for("admin_reset_approve", token=token)
        ok, err = _relay(
            admin, f"Approve a password reset for {company}",
            f"<p>Someone asked to reset the admin password for the <b>{company}</b> portal. "
            f"If you expected this, approve it and a reset link will be emailed to {user}.</p>"
            f'<p><a class="btn btn-approve" href="{link}">Review the request</a></p>'
            '<p style="font-size:12px;color:#888">The link works for 24 hours. If you didn\'t '
            "expect this, ignore the email and nothing changes.</p>")
        _audit("reset_requested", {"emailed_admin": ok})
        if not ok:
            return _simple("Couldn't send the request",
                           f"The approval email to the admin didn't go out ({err}). Contact them directly.")
        return _simple("Request sent",
                       "The admin has been emailed to approve the reset. Once they do, the link "
                       "to set a new password goes to the main user's inbox.")

    @app.route("/admin/reset/approve/<token>", methods=["GET", "POST"])
    def admin_reset_approve(token):
        req = _reset_request(token, "reset-approve")
        if not req or req.get("status") != "pending":
            return _simple("Link expired", "This approval link has expired or was already used."), 410
        user = (shared_settings.load(force=True).get("portal") or {}).get("reset_email")
        if request.method == "GET":
            # A button, not the link itself, approves: mail scanners open links.
            return _simple("Approve the password reset?",
                           f"A reset link will be emailed to {user}. It works once, for 24 hours.",
                           form="approve")
        _check_csrf()
        token = signer.dumps(req["id"], salt="reset-set")
        link = _base_url() + url_for("admin_reset_set", token=token)
        ok, err = _relay(
            user, f"Set a new password for {company}",
            f"<p>Your request to reset the <b>{company}</b> admin password was approved.</p>"
            f'<p><a class="btn btn-approve" href="{link}">Set a new password</a></p>'
            '<p style="font-size:12px;color:#888">The link works once, for 24 hours.</p>')
        if not ok:
            return _simple("Couldn't send the reset link", f"The email didn't go out ({err}).")
        _doc(RESET_DOC).set({**req, "status": "approved", "approved_at": _now()})
        _audit("reset_approved", {})
        return _simple("Approved", f"A link to set a new password has been emailed to {user}.")

    @app.route("/admin/reset/set/<token>", methods=["GET", "POST"])
    def admin_reset_set(token):
        req = _reset_request(token, "reset-set")
        if not req or req.get("status") != "approved":
            return _simple("Link expired", "This reset link has expired or was already used."), 410
        if request.method == "POST":
            _check_csrf()
            new, confirm = request.form.get("new", ""), request.form.get("confirm", "")
            if new != confirm:
                flash("The two passwords don't match.", "err")
            elif len(new) < MIN_PASSWORD:
                flash(f"Use at least {MIN_PASSWORD} characters.", "err")
            else:
                _doc(AUTH_DOC).set({"hash": generate_password_hash(new), "updated_at": _now()})
                _doc(RESET_DOC).set({**req, "status": "used", "used_at": _now()})
                _audit("password_reset", {})
                return _simple("Password changed",
                               Markup('Your new password is set. <a href="/admin">Sign in</a>.'))
        return _simple("Set a new password", "", form="set")


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


RESET_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Password reset &middot; {{ company }}</title><style>{{ style|safe }}</style></head>
<body>
<div class="topbar"><b>{{ company }}</b><span>Admin</span></div>
<div class="wrap">
  <h1>{{ title }}</h1>
  {% for cat, text in messages %}<p class="err">{{ text }}</p>{% endfor %}
  {% if body %}<p>{{ body }}</p>{% endif %}
  {% if form == 'request' %}
  <form class="login" method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button type="submit">Ask the admin to approve a reset</button></form>
  {% elif form == 'approve' %}
  <form class="login" method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    <button type="submit">Approve the reset</button></form>
  {% elif form == 'set' %}
  <form class="login" method="post"><input type="hidden" name="csrf" value="{{ csrf }}">
    <label for="new">New password (at least {{ min_pw }} characters)</label>
    <input id="new" name="new" type="password" autocomplete="new-password" required>
    <label for="confirm">New password again</label>
    <input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
    <button type="submit">Set password</button></form>
  {% endif %}
  <footer><a href="/">Back to tools</a></footer>
</div></body></html>"""
