"""Optional owner portal. No admin routes and no mailbox provisioning."""

import hmac
import html
import ipaddress
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from chatmaild.doveauth import verify_password

from .credentials import activate_destination
from .drive import Drive
from .incarnation import Mailbox
from .model import DRIVE_SCOPE, ArchiveError, subject
from .store import digest

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
COOKIE = "__Host-chatmail_archive"


def verify_google(token, audience, nonce):
    from google.auth.transport.requests import Request
    from google.oauth2.id_token import verify_oauth2_token

    try:
        request = Request()

        def bounded_request(url, method="GET", body=None, headers=None, **_kwargs):
            return request(url, method=method, body=body, headers=headers, timeout=20)

        claims = verify_oauth2_token(token, bounded_request, audience=audience)
        if (
            claims.get("nonce") != nonce
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] <= time.time()
        ):
            raise ArchiveError("invalid_identity")
        return subject(claims.get("iss"), claims.get("sub"))
    except ArchiveError:
        raise
    except Exception as exc:
        raise ArchiveError("invalid_identity") from exc


def _valid_proof_address(config, address, password):
    """Never call DoveAuth.create_user: unknown proof must remain unknown."""
    if (
        not isinstance(address, str)
        or not isinstance(password, str)
        or len(address) > 320
        or len(password) > 1024
    ):
        return False
    if (
        address.count("@") != 1
        or address.rsplit("@", 1)[1] != config.mail_domain
        or any(c in address for c in ("/", "\\", "\0"))
    ):
        return False
    return True


@contextmanager
def proven_mailbox(config, address, password):
    if not _valid_proof_address(config, address, password):
        raise ArchiveError("mailbox_proof_denied")
    try:
        config.get_user(
            address
        )  # Existing relay address validation, never provisioning.
        with Mailbox(config.mailboxes_dir, address) as mailbox:
            if not verify_password(mailbox.password.decode("ascii"), password):
                raise ArchiveError("mailbox_proof_denied")
            mailbox.check_paths()
            yield mailbox
            mailbox.check_paths()
    except (ValueError, OSError, UnicodeError) as exc:
        raise ArchiveError("mailbox_proof_denied") from exc


def prove_existing(config, address, password):
    try:
        with proven_mailbox(config, address, password):
            return True
    except ArchiveError:
        return False


class Portal:
    def __init__(
        self,
        store,
        config,
        credentials,
        public_url,
        *,
        verify=verify_google,
        drive_factory=Drive,
    ):
        if not public_url.startswith("https://") or urlsplit(public_url).path not in (
            "",
            "/",
        ):
            raise ValueError("HTTPS public origin required")
        self.store, self.config, self.credentials = store, config, credentials
        self.public_url = public_url.rstrip("/")
        self.redirect_uri = self.public_url + "/archive/callback"
        self.verify, self.drive_factory = verify, drive_factory

    def session(self, raw=None, *, create=True):
        if raw and len(raw) <= 128:
            with self.store.connect() as db:
                db.row_factory = sqlite3.Row
                row = db.execute(
                    "SELECT * FROM sessions WHERE id_hash=? AND expires>?",
                    (digest(raw), time.time()),
                ).fetchone()
                if row:
                    return raw, dict(row)
        if not create:
            return None
        raw, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.connect() as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
            if db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 10000:
                raise ArchiveError("session_saturated")
            db.execute(
                "INSERT INTO sessions(id_hash,csrf_hash,expires) VALUES(?,?,?)",
                (digest(raw), digest(csrf), time.time() + 3600),
            )
        return self.session(raw)

    def csrf(self, session):
        token = secrets.token_urlsafe(32)
        with self.store.connect() as db:
            db.execute(
                "UPDATE sessions SET csrf_hash=? WHERE id_hash=?",
                (digest(token), session["id_hash"]),
            )
        return token

    def mutation(self, session, form):
        if not hmac.compare_digest(digest(form.get("csrf", "")), session["csrf_hash"]):
            raise ArchiveError("csrf_denied")

    def personal_binding(self, binding_id, owner):
        b = self.store.get(binding_id, owner=owner)
        if b.mode != "personal" or b.retired:
            raise ArchiveError("binding_denied")
        self.check_binding(b)
        return b

    def check_binding(self, b):
        try:
            with Mailbox(self.config.mailboxes_dir, b.mailbox) as mailbox:
                mailbox.check(b.incarnation)
        except ArchiveError:
            self.store.invalidate_incarnation(b.id)
            raise

    def begin(self, session, purpose="login", binding_id=None):
        generation = None
        baseline = None
        if purpose == "drive":
            b = self.personal_binding(binding_id, session["owner"])
            if b.mode != "personal" or not b.enabled:
                raise ArchiveError("binding_denied")
            generation = b.generation
            baseline = b.credential_ref
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.store.connect() as db:
            db.execute(
                "UPDATE sessions SET state_hash=?,nonce=?,purpose=?,binding_id=?,binding_generation=?,oauth_expires=?,binding_credential_ref=? WHERE id_hash=?",
                (
                    digest(state),
                    nonce,
                    purpose,
                    binding_id,
                    generation,
                    time.time() + 600,
                    baseline,
                    session["id_hash"],
                ),
            )
        query = {
            "client_id": self.credentials.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": "openid email" + (" " + DRIVE_SCOPE if purpose == "drive" else ""),
            "state": state,
            "nonce": nonce,
        }
        if purpose == "drive":
            query.update(
                access_type="offline", prompt="consent", include_granted_scopes="true"
            )
        return AUTH_URL + "?" + urlencode(query)

    def callback(self, session, query):
        state = query.get("state", "")
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT state_hash,nonce,purpose,binding_id,owner,binding_generation,oauth_expires,binding_credential_ref FROM sessions WHERE id_hash=? AND expires>?",
                (session["id_hash"], time.time()),
            ).fetchone()
            if not row or not row[0] or not hmac.compare_digest(row[0], digest(state)):
                raise ArchiveError("oauth_state_denied")
            # Consume once before token exchange, including declined callbacks.
            db.execute(
                "UPDATE sessions SET state_hash=NULL,nonce=NULL,purpose=NULL,binding_id=NULL,binding_generation=NULL,oauth_expires=NULL,binding_credential_ref=NULL WHERE id_hash=?",
                (session["id_hash"],),
            )
        _, nonce, purpose, binding_id, owner, generation, expires, baseline = row
        if not expires or expires <= time.time():
            raise ArchiveError("oauth_transaction_expired")
        if purpose == "drive":
            pending = self.store.get(binding_id, owner=owner)
            if not pending.enabled or pending.generation != generation:
                raise ArchiveError("stale_generation")
            self.check_binding(pending)
        if "error" in query:
            if purpose == "drive":
                self.store.get(binding_id, owner=owner)
                self.store.pause(
                    binding_id, "declined", generation=generation, expected_ref=baseline
                )
            self.store.event("oauth_declined", binding_id)
            return
        code = query.get("code", "")
        if not code or len(code) > 4096:
            raise ArchiveError("oauth_code_missing")
        tokens = self.credentials.exchange(code, self.redirect_uri)
        verified_owner = self.verify(
            tokens.get("id_token", ""), self.credentials.client_id, nonce
        )
        if purpose == "login":
            # Rotate ID on sign-in in the HTTP handler; state is already consumed.
            with self.store.connect() as db:
                db.execute(
                    "UPDATE sessions SET owner=? WHERE id_hash=?",
                    (verified_owner, session["id_hash"]),
                )
            self.store.event("owner_signed_in")
            return
        if purpose != "drive" or not owner or verified_owner != owner:
            raise ArchiveError("google_account_mismatch")
        b = self.store.get(binding_id, owner=owner)
        if not b.enabled or b.generation != generation:
            raise ArchiveError("stale_generation")
        if DRIVE_SCOPE not in tokens.get("scope", "").split():
            self.store.pause(
                binding_id, "pending", generation=generation, expected_ref=baseline
            )
            self.store.event("drive_consent_missing", binding_id)
            return
        drive = self.drive_factory(tokens["access_token"])
        permission_id = drive.principal()
        if b.permission_id and permission_id != b.permission_id:
            raise ArchiveError("drive_principal_changed")
        activate_destination(
            self.store,
            self.credentials,
            b,
            permission_id,
            tokens,
            drive,
            lambda: self.check_binding(b),
            expected_ref=baseline,
        )
        self.store.enqueue(b.id)

    def link(self, session, form):
        if not session["owner"]:
            raise ArchiveError("mailbox_proof_denied")
        binding = None
        try:
            with proven_mailbox(
                self.config, form.get("mailbox", ""), form.get("password", "")
            ) as mailbox:
                incarnation = mailbox.ensure_marker()
                mailbox.check(incarnation)
                binding = self.store.bind(
                    session["owner"], form["mailbox"], incarnation=incarnation
                )
                mailbox.check(incarnation)
                return binding
        except ArchiveError:
            if binding is not None:
                self.store.invalidate_incarnation(binding.id)
            raise

    def page(self, session):
        csrf = self.csrf(session)
        token = '<input type="hidden" name="csrf" value="' + csrf + '">'
        body = "<h1>Encrypted mailbox archive</h1><p>Link an existing mailbox. Google sign-in does not create a mailbox.</p>"
        if not session["owner"]:
            body += (
                '<form method="post" action="/archive/login">'
                + token
                + "<button>Sign in with Google</button></form>"
            )
        else:
            body += "<p>Personal archiving defaults on after ownership proof, pending your explicit Drive consent. Declining Drive access keeps sign-in working.</p>"
            body += (
                '<form method="post" action="/archive/link">'
                + token
                + '<label>Existing mailbox <input name="mailbox" maxlength="320" required></label><label>Mailbox password <input type="password" name="password" maxlength="1024" required autocomplete="current-password"></label><button>Prove ownership and link</button></form>'
            )
            for b in self.store.owned(session["owner"]):
                if b.mode != "personal":
                    continue
                body += (
                    "<h2>"
                    + html.escape(b.mailbox)
                    + "</h2><p>Archive: "
                    + html.escape(b.consent)
                    + "</p>"
                )
                if b.retired:
                    body += "<p>This mailbox instance ended. Its archive history remains with its original owner. Fresh mailbox password proof is required to link the current instance.</p>"
                    continue
                unresolved = self.store.unresolved(b.id)
                body += (
                    "<p>Coverage: "
                    + (
                        "INCOMPLETE — "
                        + str(len(unresolved))
                        + " unresolved source entries"
                        if unresolved
                        else "No unresolved source entries; capture and upload jobs may still be pending"
                    )
                    + ".</p>"
                )
                if unresolved:
                    body += (
                        '<form method="post" action="/archive/retry-sources">'
                        + token
                        + '<input type="hidden" name="binding" value="'
                        + b.id
                        + '"><button>Retry unresolved source entries</button></form>'
                    )
                body += "<p>Encrypted archives are additive; existing Drive files remain after opt-out. Recovery keys are held in the operator wallet; independent owner key recovery is not configured.</p>"
                body += (
                    '<form method="post" action="/archive/consent">'
                    + token
                    + '<input type="hidden" name="binding" value="'
                    + b.id
                    + '"><button>Enable / reconnect personal Drive archive</button></form>'
                )
                body += (
                    '<form method="post" action="/archive/optout">'
                    + token
                    + '<input type="hidden" name="binding" value="'
                    + b.id
                    + '"><button>Turn off future archiving</button></form>'
                )
                with self.store.connect() as db:
                    rows = db.execute(
                        "SELECT state,last_reason,updated FROM jobs WHERE binding_id=? ORDER BY updated DESC LIMIT 5",
                        (b.id,),
                    ).fetchall()
                body += (
                    "<ul>"
                    + "".join(
                        "<li>"
                        + html.escape(state + (": " + reason if reason else ""))
                        + "</li>"
                        for state, reason, _ in rows
                    )
                    + "</ul>"
                )
            body += (
                '<form method="post" action="/archive/logout">'
                + token
                + "<button>Sign out</button></form>"
            )
        return (
            '<!doctype html><html><head><meta charset="utf-8"><title>Mailbox archive</title></head><body>'
            + body
            + "</body></html>"
        ).encode()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        # OAuth codes and proof bodies must never enter access logs.
        pass

    def do_GET(self):
        self.handle_route()

    def do_POST(self):
        self.handle_route()

    def handle_route(self):
        portal = self.server.portal
        raw = None
        started = time.monotonic()
        try:
            if len(self.path) > 8192:
                raise ArchiveError("request_rate_or_size")
            cookies = SimpleCookie(self.headers.get("Cookie", ""))
            existing = portal.session(
                cookies[COOKIE].value if COOKIE in cookies else None, create=False
            )
            client = self.server.client_key(
                self.client_address[0],
                self.headers.get_all("X-Chatmail-Archive-Client", []),
            )
            if not self.server.admit(
                client, owner=existing[1]["owner"] if existing else None
            ):
                raise ArchiveError("client_request_rate")
            if not self.server.admit_global():
                raise ArchiveError("aggregate_request_rate")
            raw, session = existing or portal.session()
            parsed = urlsplit(self.path)
            path = parsed.path
            if self.command == "GET":
                if path in ("/archive", "/archive/"):
                    return self.reply(200, raw, portal.page(session))
                if path == "/archive/callback":
                    query = self.parameters(parsed.query)
                    portal.callback(session, query)
                    # Rotate the session cookie after every OAuth callback.
                    _, updated = portal.session(raw)
                    new_raw, new_session = portal.session()
                    with portal.store.transaction() as db:
                        db.execute(
                            "UPDATE sessions SET owner=? WHERE id_hash=?",
                            (updated["owner"], new_session["id_hash"]),
                        )
                        db.execute(
                            "DELETE FROM sessions WHERE id_hash=?",
                            (session["id_hash"],),
                        )
                    return self.reply(303, new_raw, location="/archive/")
            elif self.command == "POST":
                if (
                    self.headers.get("Content-Type", "").split(";", 1)[0]
                    != "application/x-www-form-urlencoded"
                ):
                    raise ArchiveError("body_type_denied")
                length = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= length <= 4096:
                    raise ArchiveError("body_limit")
                form = self.parameters(self.rfile.read(length).decode("utf-8"))
                portal.mutation(session, form)
                if path == "/archive/login":
                    return self.reply(303, raw, location=portal.begin(session))
                if not session["owner"]:
                    raise ArchiveError("owner_signin_required")
                if path == "/archive/link":
                    portal.link(session, form)
                elif path == "/archive/consent":
                    b = portal.personal_binding(
                        form.get("binding", ""), session["owner"]
                    )
                    portal.store.enable(b.id, session["owner"])
                    return self.reply(
                        303, raw, location=portal.begin(session, "drive", b.id)
                    )
                elif path == "/archive/optout":
                    b = portal.personal_binding(
                        form.get("binding", ""), session["owner"]
                    )
                    portal.store.optout(b.id, session["owner"])
                elif path == "/archive/retry-sources":
                    b = portal.personal_binding(
                        form.get("binding", ""), session["owner"]
                    )
                    portal.store.retry_sources(b.id)
                elif path == "/archive/logout":
                    with portal.store.connect() as db:
                        db.execute(
                            "DELETE FROM sessions WHERE id_hash=?",
                            (session["id_hash"],),
                        )
                    raw = None
                else:
                    return self.reply(404, raw)
                return self.reply(303, raw, location="/archive/")
            self.reply(404, raw)
        except ArchiveError as exc:
            portal.store.event(exc.reason)
            self.reply(
                400,
                raw,
                b"Archive action could not complete. Sign-in remains separate from Drive consent. Return to /archive/ to retry.",
            )
        except Exception:
            portal.store.event("portal_request_failed")
            self.reply(
                400,
                raw,
                b"Archive action could not complete. Return to /archive/ to retry.",
            )
        finally:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            portal.store.event("portal_request_ms", amount=elapsed_ms)
            if elapsed_ms > 1000:
                portal.store.event("portal_slow_request")

    @staticmethod
    def parameters(query):
        values = parse_qs(query, keep_blank_values=True, max_num_fields=12)
        if any(len(v) != 1 for v in values.values()):
            raise ArchiveError("duplicate_parameter")
        return {key: value[0] for key, value in values.items()}

    def reply(self, status, session_id, body=b"", location=None):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        self.send_header(
            "Set-Cookie",
            COOKIE
            + "="
            + (session_id or "")
            + "; Path=/; Secure; HttpOnly; SameSite=Lax"
            + ("; Max-Age=3600" if session_id else "; Max-Age=0"),
        )
        if location:
            self.send_header("Location", location)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 32

    def __init__(self, address, portal, workers=8, trusted_proxy="127.0.0.1"):
        if address[0] not in ("127.0.0.1", "::1"):
            raise ValueError("portal must bind loopback behind TLS proxy")
        self.portal, self.slots = portal, threading.BoundedSemaphore(workers)
        self.rate, self.rate_lock = OrderedDict(), threading.Lock()
        self.trusted_proxy = trusted_proxy
        self.stalls = 0
        self.audit_stop = threading.Event()
        super().__init__(address, Handler)
        self.audit_thread = threading.Thread(target=self.flush_stalls, daemon=True)
        self.audit_thread.start()

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            # The accept thread never writes the ledger. A dedicated collector
            # aggregates every rejected request into the existing store.
            with self.rate_lock:
                self.stalls += 1
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def client_key(self, peer, headers):
        peer_ip = str(ipaddress.ip_address(peer))
        if peer_ip != self.trusted_proxy or not headers:
            return "ip:" + peer_ip
        if len(headers) != 1:
            raise ArchiveError("proxy_client_header_denied")
        try:
            canonical = str(ipaddress.ip_address(headers[0]))
        except ValueError as exc:
            raise ArchiveError("proxy_client_header_denied") from exc
        if canonical != headers[0]:
            raise ArchiveError("proxy_client_header_denied")
        return "ip:" + canonical

    def admit_global(self):
        return self._admit("aggregate", 3000)

    def admit(self, address, *, owner=None):
        return self._admit("owner:" + owner if owner else address, 60)

    def _admit(self, key, limit):
        now = int(time.time() // 60)
        with self.rate_lock:
            for existing in list(self.rate):
                if self.rate[existing][0] != now:
                    del self.rate[existing]
            previous, count = self.rate.get(key, (now, 0))
            if len(self.rate) >= 4096 and key not in self.rate:
                return False
            self.rate[key] = (previous, count + 1)
            return count < limit

    def flush_stalls(self):
        while True:
            stopped = self.audit_stop.wait(1)
            with self.rate_lock:
                count, self.stalls = self.stalls, 0
            if count:
                try:
                    self.portal.store.event("portal_worker_stall", amount=count)
                except Exception:
                    with self.rate_lock:
                        self.stalls += count
            if stopped:
                break

    def server_close(self):
        if hasattr(self, "audit_thread"):
            self.audit_stop.set()
            self.audit_thread.join(timeout=3)
        super().server_close()
