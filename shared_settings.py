"""Shared settings for the property tools, edited on the portal's Settings page.

The portal writes one Firestore document, property_tools/settings. Each tool
(Capital, Expense, Incident) reads it when it needs a value, cached for a
minute, and falls back to its own env vars for anything the page has not set.
If Firestore cannot be reached the tools keep their last good copy, or their env
defaults, so a settings outage never stops a submission or an email.

The same file is copied into each tool's repo. Keep the copies identical.

Document shape (every key optional):

    email:    {send_via: "outlook" | "service", from_address, from_name, reply_to}
    portal:   {contact_name, admin_email, reset_email}
    capital:  {approver_name, approver_email, approval_copies: [..], signature}
    expense:  {approver_name, approver_email, review_cc: [..], approved_copies: [..], signature}
    incident: {approver_name, approver_email, cc: [..], carrier_email}

`signature` is "uploaded" (image in property_tools/signature_<tool>) or
"none" (typed name). Absent means the tool's own SIGNATURE_PATH / file.

"service" sends through Resend's HTTP API with the RESEND_API_KEY env var on
each service, so no mailbox, password or Outlook setting is involved.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request
from email.utils import formataddr

COLLECTION = "property_tools"
SETTINGS_DOC = "settings"
CACHE_SECONDS = 60
RESEND_URL = "https://api.resend.com/emails"

_cache = {"at": 0.0, "data": {}}


def _firestore_enabled():
    # Locally there are usually no Google credentials; don't make every page
    # load wait on a failed lookup. On Cloud Run (K_SERVICE) it is always on.
    return bool(os.environ.get("K_SERVICE") or os.environ.get("SHARED_SETTINGS_FIRESTORE"))


def _db():
    from google.cloud import firestore
    return firestore.Client()


def load(force=False):
    """The whole settings document, at most CACHE_SECONDS old."""
    now = time.time()
    if not force and now - _cache["at"] < CACHE_SECONDS:
        return _cache["data"]
    data = _cache["data"]
    if _firestore_enabled():
        try:
            snap = _db().collection(COLLECTION).document(SETTINGS_DOC).get()
            data = (snap.to_dict() or {}) if snap.exists else {}
        except Exception as e:  # keep the last good copy; retry next window
            print(f"[settings] could not read shared settings ({type(e).__name__}); "
                  "using last known values")
    _cache.update(at=now, data=data)
    return data


def get(section, key, default=None):
    """One value. A blank string falls back to `default` (an approver can't be
    nobody), but a list that was saved empty stays empty, so removing the last
    person from a copy list really removes them."""
    sec = load().get(section) or {}
    if key not in sec:
        return default
    value = sec[key]
    if isinstance(value, str) and not value.strip():
        return default
    return value


def get_list(section, key, default):
    value = get(section, key, None)
    if value is None:
        return list(default)
    if isinstance(value, str):
        value = value.split(",")
    return [v.strip() for v in value if v and v.strip()]


# --- Email service ---------------------------------------------------------

def service_selected():
    return get("email", "send_via", "outlook") == "service"


def service_ready():
    return bool(os.environ.get("RESEND_API_KEY") and get("email", "from_address"))


def use_service():
    """True when the Settings page chose the email service and it is usable.
    If it was chosen but isn't usable yet (no key or no from-address), the
    tools keep sending through Outlook rather than going silent."""
    if not service_selected():
        return False
    if not service_ready():
        print("[settings] email service selected but RESEND_API_KEY or from address "
              "is missing; sending through Outlook instead")
        return False
    return True


def sender_label():
    """What the Settings page shows as 'currently sending from'."""
    if use_service():
        return f"email service as {get('email', 'from_address')}"
    return "Outlook"


def send_via_service(to, subject, html, cc=None, attachments=None):
    """Send one HTML email through Resend. `attachments` is [(filename, bytes)].
    Raises RuntimeError on failure so callers handle it like an SMTP error."""
    to = [a for a in ([to] if isinstance(to, str) else list(to or [])) if a]
    cc = [a for a in ([cc] if isinstance(cc, str) else list(cc or [])) if a]
    if not to:
        raise RuntimeError("no recipients")
    payload = {
        "from": formataddr((get("email", "from_name", "Property Tools"),
                            get("email", "from_address"))),
        "to": to,
        "subject": subject,
        "html": html,
    }
    if cc:
        payload["cc"] = cc
    reply_to = get("email", "reply_to")
    if reply_to:
        payload["reply_to"] = reply_to
    if attachments:
        payload["attachments"] = [
            {"filename": name, "content": base64.b64encode(data).decode()}
            for name, data in attachments]
    req = urllib.request.Request(
        RESEND_URL, data=json.dumps(payload).encode(), method="POST",
        headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}",
                 "Content-Type": "application/json",
                 "User-Agent": "wright-property-tools/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if not 200 <= resp.status < 300:
                raise RuntimeError(f"email service returned HTTP {resp.status}")
    except urllib.error.HTTPError as e:
        # The body explains what's wrong (unverified domain, bad key) and
        # carries no recipient data, so it is safe to log.
        detail = e.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"email service returned HTTP {e.code}: {detail}") from None
    return True


# --- Approval signature ----------------------------------------------------

_sig_cache = {}


def signature_override(tool, approver_name):
    """Which signature image `tool` should stamp on an approval.

    None  -> the Settings page has no say; use the tool's own signature file.
    ""    -> print the typed name, no image.
    path  -> a local copy of the uploaded image.

    An uploaded image is only used while it belongs to the current approver,
    so changing the approver can never put the new name next to the old
    person's signature.
    """
    mode = get(tool, "signature")
    if mode is None:
        return None
    if mode != "uploaded":
        return ""
    try:
        snap = _db().collection(COLLECTION).document(f"signature_{tool}").get()
        doc = snap.to_dict() if snap.exists else None
    except Exception as e:
        print(f"[settings] could not read {tool} signature ({type(e).__name__}); using typed name")
        return ""
    if not doc or not doc.get("data") or doc.get("approver_name") != approver_name:
        return ""
    key = (tool, doc.get("updated_at"))
    path = _sig_cache.get(key)
    if not path or not os.path.exists(path):
        import tempfile
        ext = ".png" if doc.get("content_type") == "image/png" else ".jpg"
        fd, path = tempfile.mkstemp(prefix=f"signature_{tool}_", suffix=ext)
        with os.fdopen(fd, "wb") as f:
            f.write(bytes(doc["data"]))
        _sig_cache[key] = path
    return path


def read_attachment(path, filename=None):
    """(filename, bytes) for a file on disk, or None if it's missing."""
    if not path or not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return (filename or os.path.basename(path), f.read())
