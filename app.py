"""Internal tools portal - one front door for the three Cloud Run apps,
plus a password-protected /admin console linking each app's reviewer side.

Public page: no auth, just directs staff to the right tool.
Admin console (/admin): gated by PORTAL_PASSWORD. After login, the links
carry each app's admin token (from env) so one click opens each dashboard
already authenticated. Tokens are never rendered before login.

Env vars:
  CAPITAL_URL / EXPENSE_URL / INCIDENT_URL   tool addresses (defaults baked in)
  COMPANY_NAME                               header label (default "Property Tools")
  PORTAL_PASSWORD                            enables /admin (unset = disabled)
  FLASK_SECRET                               session signing (required for /admin)
  INCIDENT_ADMIN_TOKEN / CAPITAL_ADMIN_TOKEN / EXPENSE_ADMIN_TOKEN
                                             each app's ADMIN_TOKEN (optional)
"""
import os
import time

from flask import (Flask, redirect, render_template_string, request, session,
                   url_for)

import settings_page
import shared_settings

# IMPORTANT: each URL here must match that app's own BASE_URL env var exactly.
#
# Cloud Run publishes every service under two equivalent hostnames — the
# project-number form (`<svc>-55680138488.us-central1.run.app`) and the hash
# form (`<svc>-u3zy5zun5a-uc.a.run.app`). Both serve the same container, so a
# mismatch looks harmless and tests fine. It is not: they are different
# origins, so they have different cookie jars. Sign in through the portal on
# one hostname and the session cookie simply does not exist on the other, and
# every e-mailed link (built from BASE_URL) lands you at a login form for an
# app you are already signed in to.
#
# Today: capital + expense use the project-number form on both sides, incidents
# uses the hash form on both sides. Consistent per app, which is all that
# matters. If you ever change one side, change the other in the same breath.
CAPITAL_URL = os.environ.get(
    "CAPITAL_URL", "https://capital-expense-approval-portal-55680138488.us-central1.run.app")
EXPENSE_URL = os.environ.get(
    "EXPENSE_URL", "https://xpenser-55680138488.us-central1.run.app")
INCIDENT_URL = os.environ.get(
    "INCIDENT_URL", "https://incidents-u3zy5zun5a-uc.a.run.app")
COMPANY = os.environ.get("COMPANY_NAME", "Property Tools")
PORTAL_PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
INCIDENT_ADMIN_TOKEN = os.environ.get("INCIDENT_ADMIN_TOKEN", "")
CAPITAL_ADMIN_TOKEN = os.environ.get("CAPITAL_ADMIN_TOKEN", "")
EXPENSE_ADMIN_TOKEN = os.environ.get("EXPENSE_ADMIN_TOKEN", "")

ON_CLOUD_RUN = bool(os.environ.get("K_SERVICE"))


def _flask_secret():
    """Session signing key — never a hardcoded default.

    The old fallback ("dev-portal-secret") is a publicly known string in this
    file: if the env var were ever missing on the deployed service, anyone
    could forge a `portal_admin` cookie and skip the password entirely. In
    production we refuse to start; locally we mint a random key per process.
    """
    secret = os.environ.get("FLASK_SECRET", "").strip()
    if secret:
        return secret
    if ON_CLOUD_RUN:
        raise RuntimeError(
            "FLASK_SECRET is not set. Refusing to start: the admin session "
            "cookie would be signed with a guessable key.")
    import secrets
    print("[portal] FLASK_SECRET unset — random per-process key (local dev only).")
    return secrets.token_urlsafe(48)


app = Flask(__name__)
app.secret_key = _flask_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=ON_CLOUD_RUN)

STYLE = """
* { box-sizing:border-box; }
body { margin:0; background:#f4f5f7; color:#1c2733;
       font:15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif; }
.topbar { background:#16283c; color:#fff; padding:.85rem 1.4rem; }
.topbar b { font-size:1.05rem; letter-spacing:.02em; }
.topbar span { color:#8fa3b8; font-size:.82rem; margin-left:.7rem; }
.wrap { max-width:680px; margin:0 auto; padding:2.4rem 1.2rem; }
a.row { display:flex; align-items:center; gap:1.1rem; background:#fff;
        border:1px solid #d8dee6; border-radius:6px; padding:1.05rem 1.2rem;
        margin-bottom:.8rem; text-decoration:none; color:inherit; }
a.row:hover { border-color:#3a5a7d; }
a.row:hover h2 { text-decoration:underline; }
.row svg { flex:none; width:26px; height:26px; stroke:#3a5a7d; }
.row h2 { font-size:1.02rem; margin:0 0 .15rem; color:#1f4e79; font-weight:600; }
.row p { margin:0; font-size:.88rem; color:#5b6b7b; }
footer { margin-top:2rem; font-size:.82rem; color:#8a97a5; }
footer a { color:#8a97a5; }
h1 { font-size:1.2rem; margin:0 0 1.2rem; }
form.login { background:#fff; border:1px solid #d8dee6; border-radius:6px;
             padding:1.4rem; max-width:360px; }
form.login label { display:block; font-size:.85rem; font-weight:600; margin-bottom:.3rem; }
form.login input { width:100%; font:inherit; padding:.5rem .6rem;
                   border:1px solid #c5ced8; border-radius:4px; margin-bottom:.9rem; }
form.login button { font:inherit; padding:.5rem 1.1rem; border:0; border-radius:4px;
                    background:#1f4e79; color:#fff; cursor:pointer; }
.err { color:#a13030; font-size:.88rem; margin:0 0 .8rem; }
.reveal { font-size:.82rem; color:#5b6b7b; margin-top:.3rem; }
.reveal code { background:#eef1f4; padding:.1rem .35rem; border-radius:3px; }
details summary { cursor:pointer; }
"""

ICON_BRIEFCASE = """<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/></svg>"""
ICON_FILE = """<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>"""
ICON_ALERT = """<svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>"""

PUBLIC_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ company }}</title><style>""" + STYLE + """</style></head>
<body>
<div class="topbar"><b>{{ company }}</b><span>For internal use only</span></div>
<div class="wrap">
  <a class="row" href="{{ capital_url }}">""" + ICON_BRIEFCASE + """
    <div><h2>Capital Authorizations</h2>
    <p>Submit a capital expenditure request for approval.</p></div></a>
  <a class="row" href="{{ expense_url }}">""" + ICON_FILE + """
    <div><h2>Expense Reports</h2>
    <p>Upload a signed expense report and receipts.</p></div></a>
  <a class="row" href="{{ incident_url }}">""" + ICON_ALERT + """
    <div><h2>Incident Reports</h2>
    <p>Report a guest injury or property damage. Reviewed before anything is filed.</p></div></a>
  <footer>{% if contact %}Questions: {{ contact }} &middot; {% endif %}<a href="/admin">Admin</a></footer>
</div></body></html>"""

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin &middot; {{ company }}</title><style>""" + STYLE + """</style></head>
<body>
<div class="topbar"><b>{{ company }}</b><span>Admin</span></div>
<div class="wrap">
  <h1>Reviewer sign-in</h1>
  {% if error %}<p class="err">{{ error }}</p>{% endif %}
  <form class="login" method="post">
    <label for="pw">Password</label>
    <input id="pw" name="password" type="password" autofocus autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
  <p class="reveal"><a href="/admin/forgot">Forgot password?</a></p>
  <footer><a href="/">Back to tools</a></footer>
</div></body></html>"""

ADMIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin &middot; {{ company }}</title><style>""" + STYLE + """
form.row { display:flex; align-items:center; gap:1.1rem; background:#fff;
           border:1px solid #d8dee6; border-radius:6px; padding:1.05rem 1.2rem;
           margin-bottom:.8rem; width:100%; text-align:left; cursor:pointer; }
form.row:hover { border-color:#3a5a7d; }
form.row:hover h2 { text-decoration:underline; }
form.row button { all:unset; cursor:pointer; flex:1; }
form.row h2 { font-size:1.02rem; margin:0 0 .15rem; color:#1f4e79; font-weight:600; }
form.row p { margin:0; font-size:.88rem; color:#5b6b7b; }
</style></head>
<body>
<div class="topbar"><b>{{ company }}</b><span>Admin console</span></div>
<div class="wrap">
  <h1>Review dashboards</h1>

  {# Each dashboard is opened by POSTing its token to that app's sign-in
     endpoint, so the token stays in the request body and never lands in a
     URL, browser history, or an access log. #}
  <form class="row" method="post" action="{{ capital.login or capital.fallback }}" target="_blank">
    {% if capital.token %}<input type="hidden" name="token" value="{{ capital.token }}">
    <input type="hidden" name="next" value="{{ capital.next }}">{% endif %}
    """ + ICON_BRIEFCASE + """
    <button type="submit"><h2>Capital &mdash; submissions</h2>
    <p>Review and approve capital authorization requests.</p></button>
  </form>

  <form class="row" method="post" action="{{ expense.login or expense.fallback }}" target="_blank">
    {% if expense.token %}<input type="hidden" name="token" value="{{ expense.token }}">
    <input type="hidden" name="next" value="{{ expense.next }}">{% endif %}
    """ + ICON_FILE + """
    <button type="submit"><h2>Expenses &mdash; reviewer dashboard</h2>
    <p>Review submitted expense reports.</p></button>
  </form>

  <form class="row" method="post" action="{{ incident.login or incident.fallback }}" target="_blank">
    {% if incident.token %}<input type="hidden" name="token" value="{{ incident.token }}">
    <input type="hidden" name="next" value="{{ incident.next }}">{% endif %}
    """ + ICON_ALERT + """
    <button type="submit"><h2>Incidents &mdash; reviewer dashboard</h2>
    <p>Review incident reports, language findings, and approvals.</p></button>
  </form>

  <footer><a href="{{ url_for('settings') }}">Settings</a> &middot; <a href="/">Back to tools</a> &middot; <a href="{{ url_for('admin_logout') }}">Sign out</a></footer>
</div></body></html>"""


# --- Login throttle (F12): per-IP, in-process ------------------------------
_LOGIN_FAILURES = {}
_LOGIN_MAX_TRIES = 8
_LOGIN_WINDOW = 900


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() if fwd else request.remote_addr) or "unknown"


def _login_blocked():
    entry = _LOGIN_FAILURES.get(_client_ip())
    if not entry:
        return False
    count, first = entry
    if time.time() - first > _LOGIN_WINDOW:
        _LOGIN_FAILURES.pop(_client_ip(), None)
        return False
    return count >= _LOGIN_MAX_TRIES


def _note_login_failure():
    ip = _client_ip()
    count, first = _LOGIN_FAILURES.get(ip, (0, time.time()))
    if time.time() - first > _LOGIN_WINDOW:
        count, first = 0, time.time()
    _LOGIN_FAILURES[ip] = (count + 1, first)


def _note_login_success():
    _LOGIN_FAILURES.pop(_client_ip(), None)


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    # form-action lists the three tool origins because the admin console POSTs
    # each dashboard's token to its own sign-in endpoint (see _admin_targets).
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; "
        f"form-action 'self' {CAPITAL_URL} {EXPENSE_URL} {INCIDENT_URL}; "
        "base-uri 'none'; object-src 'none'")
    if ON_CLOUD_RUN:
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=31536000; includeSubDomains")
    return resp


def _admin_targets():
    """Where each dashboard's sign-in POST goes, and where it lands after.

    The portal used to build `?token=<ADMIN_TOKEN>` straight into an <a href>,
    which put a standing admin credential into the browser address bar, history,
    bookmarks, the Referer header, and every access log along the way. Instead
    each row is now a form that POSTs the token to that app's /login endpoint;
    the app trades it for a session cookie and redirects to a clean URL. The
    token never appears in a URL.
    """
    return [
        dict(key="capital", token=CAPITAL_ADMIN_TOKEN,
             login=f"{CAPITAL_URL}/admin/login", next="/admin/submissions",
             fallback=f"{CAPITAL_URL}/admin/submissions"),
        dict(key="expense", token=EXPENSE_ADMIN_TOKEN,
             login=f"{EXPENSE_URL}/login", next="/admin",
             fallback=f"{EXPENSE_URL}/admin"),
        dict(key="incident", token=INCIDENT_ADMIN_TOKEN,
             login=f"{INCIDENT_URL}/login", next="/admin",
             fallback=f"{INCIDENT_URL}/admin"),
    ]


@app.get("/")
def index():
    return render_template_string(PUBLIC_PAGE, company=COMPANY, capital_url=CAPITAL_URL,
                                  expense_url=EXPENSE_URL, incident_url=INCIDENT_URL,
                                  contact=shared_settings.get("portal", "contact_name", ""))


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not PORTAL_PASSWORD:
        return ("Admin console is not enabled. Set PORTAL_PASSWORD (and FLASK_SECRET) "
                "on the portal service.", 503)
    error = None
    if request.method == "POST":
        if _login_blocked():
            # A fixed 1-second sleep is not a control — an attacker can run
            # attempts in parallel. Lock the address out instead.
            return render_template_string(
                LOGIN_PAGE, company=COMPANY,
                error=("Too many failed attempts from this address. "
                       f"Try again in {_LOGIN_WINDOW // 60} minutes.")), 429
        supplied = request.form.get("password", "")
        if settings_page.check_password(supplied, PORTAL_PASSWORD):
            _note_login_success()
            session["portal_admin"] = True
            return redirect(url_for("admin"))
        _note_login_failure()
        time.sleep(1)  # slow brute-force attempts
        error = "Wrong password."
    if not session.get("portal_admin"):
        return render_template_string(LOGIN_PAGE, company=COMPANY, error=error)
    targets = {t["key"]: t for t in _admin_targets()}
    return render_template_string(ADMIN_PAGE, company=COMPANY, **targets)


@app.get("/admin/logout")
def admin_logout():
    session.pop("portal_admin", None)
    return redirect(url_for("index"))


settings_page.init_app(
    app, style=STYLE, company=COMPANY, env_password=PORTAL_PASSWORD,
    tools={"capital": {"base": CAPITAL_URL, "token": CAPITAL_ADMIN_TOKEN},
           "expense": {"base": EXPENSE_URL, "token": EXPENSE_ADMIN_TOKEN},
           "incident": {"base": INCIDENT_URL, "token": INCIDENT_ADMIN_TOKEN}})


@app.get("/healthz")
def healthz():
    return {"ok": True}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
