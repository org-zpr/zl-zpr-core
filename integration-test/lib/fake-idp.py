#!/usr/bin/env python3
"""Fake OIDC identity provider for the ZPR integration tests (zipline#16, D5).

A minimal OpenID Provider serving the four endpoints the ZPR OIDC flow
touches, so the whole relying-party path (ph-cli `connect --no-browser`,
visa-service JWKS fetch and token validation) runs with no Google and no
browser:

  GET  /.well-known/openid-configuration  discovery document
  GET  /auth                              302 to redirect_uri with code+state
                                          (no UI; nonce, client_id,
                                          redirect_uri and the PKCE challenge
                                          are remembered, keyed by the code)
  POST /token                             JSON with an RS256 id_token minted
                                          from a checked-in test key, echoing
                                          the nonce stored for the code —
                                          after checking that client_id and
                                          redirect_uri match what /auth saw
                                          and that the S256 hash of
                                          code_verifier matches the stored
                                          code_challenge, so a relying-party
                                          regression in any of those is
                                          rejected here just as Google would.
                                          Serves `grant_type=refresh_token`
                                          too — see "Refresh grants" below
  GET  /jwks                              JWKS for the currently active key,
                                          with a kid

Deliberately standard-library only. RS256 signatures are produced by
shelling out to `openssl dgst -sha256 -sign` (RSASSA-PKCS1-v1_5 with
SHA-256, exactly the JWS RS256 primitive); the openssl CLI is already an
integration-test prerequisite (docs/BUILD.md).

Serves TLS only: the compiler's `issuer` rule is https-absolute, so the
test issuer is `https://127.0.0.1:<port>` with a certificate signed by the
test CA, which clients trust via SSL_CERT_FILE / curl --cacert.

Key rotation: the server is started with two signing keys. Which one is
active lives in `<state-dir>/active-key` and is re-read on every request,
so a second invocation with `--rotate` (same --state-dir) switches the
serving process to the other key with no signal plumbing:

    fake-idp.py --state-dir "$DIR" --rotate

Refresh grants (zipline#47): an authorization request whose `scope`
carries `offline_access` gets a `refresh_token` back from the code
exchange, and `grant_type=refresh_token` renews the `id_token`. The
renewed token models the properties ZPR's silent
re-authentication depends on (zl-zpr-dev-context/docs/OIDC.md,
"Credential lifetimes and re-authentication"):
`auth_time` does NOT move (it is the human's login moment, and the visa
service anchors its session ceiling on it), `iat` strictly advances (the
visa service rejects a replay), and there is NO `nonce` claim. The last
follows OIDC Core section 12.2, which says a refreshed id_token "SHOULD NOT
have a nonce Claim, even when the ID Token issued at the time of the
original authentication contained nonce; however, if it is present, its
value MUST be the same as in the ID Token issued at the time of the original
authentication" — absent or original, never fresh, which is exactly why the
reauthorize path cannot check a nonce against a fresh challenge. Omitting it
is both the spec-preferred branch and what Google does, so it is what the
harness models; the visa service must accept either.
Revocation works like key rotation, through a file in `--state-dir` that
is re-read on every request, so one invocation reaches every serving
instance:

    fake-idp.py --state-dir "$DIR" --revoke-refresh

`--print-jwks` prints the JWKS for both keys and exits — the pregen
Makefile uses it to build the seed JWKS fixture from the same code that
serves /jwks, so the two cannot drift.
"""

import argparse
import base64
import hashlib
import json
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def b64url(data: bytes) -> str:
    """Base64url-encode without padding (RFC 7515 terminology)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def rsa_public_numbers(key_path: Path) -> tuple[bytes, bytes]:
    """Extract (modulus, exponent) big-endian bytes from an RSA private key
    by parsing `openssl rsa -noout -text` output (stdlib-only constraint)."""
    text = subprocess.run(
        ["openssl", "rsa", "-in", str(key_path), "-noout", "-text"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    mod_match = re.search(r"modulus:\n((?:\s+[0-9a-f:]+\n)+)", text)
    exp_match = re.search(r"publicExponent:\s*(\d+)", text)
    if not mod_match or not exp_match:
        raise ValueError(f"cannot parse RSA public numbers from {key_path}")
    mod_hex = re.sub(r"[\s:]", "", mod_match.group(1))
    modulus = bytes.fromhex(mod_hex).lstrip(b"\x00")
    exponent = int(exp_match.group(1))
    exp_bytes = exponent.to_bytes((exponent.bit_length() + 7) // 8, "big")
    return modulus, exp_bytes


class SigningKey:
    """One RSA signing key: its file, derived kid, and JWK."""

    def __init__(self, key_path: Path):
        self.path = key_path
        modulus, exponent = rsa_public_numbers(key_path)
        # Deterministic kid from the public key, so the seed JWKS fixture
        # (built via --print-jwks) always matches what the server serves.
        self.kid = "fake-idp-" + hashlib.sha256(modulus).hexdigest()[:16]
        self.jwk = {
            "kty": "RSA",
            "kid": self.kid,
            "use": "sig",
            "alg": "RS256",
            "n": b64url(modulus),
            "e": b64url(exponent),
        }

    def sign_rs256(self, signing_input: bytes) -> bytes:
        """RSASSA-PKCS1-v1_5 / SHA-256 over `signing_input` via the openssl
        CLI (`dgst -sha256 -sign` is exactly the JWS RS256 primitive)."""
        return subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", str(self.path)],
            input=signing_input,
            check=True,
            capture_output=True,
        ).stdout


class IdpState:
    """Server-wide state: the two keys, issued codes, and the rotation file."""

    def __init__(self, args):
        self.issuer = f"https://{args.host}:{args.port}"
        self.keys = [SigningKey(Path(args.signing_key))]
        if args.signing_key_2:
            self.keys.append(SigningKey(Path(args.signing_key_2)))
        self.client_id = args.client_id
        self.sub = args.sub
        self.email = args.email
        self.hd = args.hd
        self.state_dir = Path(args.state_dir)
        # code -> the authorization request's bindings (nonce, client_id,
        # redirect_uri, PKCE challenge), remembered by /auth so /token can
        # reject an exchange that does not match them. Codes are single use.
        self.codes: dict[str, dict] = {}
        # refresh token -> the session it renews: the original auth_time
        # (which does not move across a renewal) plus the highest `iat`
        # minted so far, so the next one can be forced strictly past it. The
        # original nonce is deliberately NOT kept — a refreshed id_token
        # omits the claim (OIDC Core 12.2's SHOULD NOT). In-process, like
        # `codes`: a netns runs its own instance and an adapter renews
        # against the one it logged in to.
        self.sessions: dict[str, dict] = {}

    def active_key(self) -> SigningKey:
        """The currently active signing key, re-read from the rotation file
        on every call so an external --rotate takes effect immediately."""
        index = read_active_index(self.state_dir)
        return self.keys[min(index, len(self.keys) - 1)]

    def mint_id_token(
        self, nonce: str | None, auth_time: int, after_iat: int = 0
    ) -> tuple[str, int]:
        """Mint an RS256 id_token with the active key and return it with the
        `iat` it carries.

        `nonce` is echoed when given and the claim is OMITTED when None. The
        refresh path passes None: OIDC Core section 12.2 says a refreshed
        id_token SHOULD NOT carry the claim, and Google does not.

        `auth_time` is passed in rather than taken from the clock because a
        refresh grant must re-present the ORIGINAL login moment: it did not
        re-authenticate the human, and the visa service anchors its session
        ceiling on that claim not moving.

        `after_iat` forces `iat` strictly past a previous token's. The visa
        service rejects a reauthorization whose `iat` did not advance, and
        `iat` has one-second granularity, so two renewals inside one
        wall-clock second would otherwise mint the identical value and the
        second would look like a replay.
        """
        key = self.active_key()
        iat = max(int(time.time()), after_iat + 1)
        header = {"alg": "RS256", "typ": "JWT", "kid": key.kid}
        claims = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": self.sub,
            "email": self.email,
            "email_verified": True,
            "hd": self.hd,
            "iat": iat,
            "auth_time": auth_time,
            "exp": iat + 3600,
        }
        if nonce is not None:
            claims["nonce"] = nonce
        signing_input = (
            b64url(json.dumps(header).encode()) + "." + b64url(json.dumps(claims).encode())
        ).encode("ascii")
        signature = key.sign_rs256(signing_input)
        return signing_input.decode("ascii") + "." + b64url(signature), iat


ACTIVE_KEY_FILE = "active-key"
REFRESH_REVOKED_FILE = "refresh-revoked"


def read_active_index(state_dir: Path) -> int:
    """Read the active key index (0-based) from the rotation file; 0 if unset."""
    try:
        return int((state_dir / ACTIVE_KEY_FILE).read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def refresh_revoked(state_dir: Path) -> bool:
    """Whether refresh grants are currently revoked. Read on every request,
    like the rotation file, so `--revoke-refresh` reaches serving instances
    in other network namespaces without any signal plumbing."""
    return (state_dir / REFRESH_REVOKED_FILE).exists()


def revoke_refresh(state_dir: Path) -> None:
    """Refuse every later refresh grant with `invalid_grant` (the
    --revoke-refresh action) — what an IdP does once the user withdraws the
    application's access."""
    (state_dir / REFRESH_REVOKED_FILE).write_text("revoked\n")
    print("refresh grants revoked")


def rotate(state_dir: Path) -> None:
    """Toggle the active key index between 0 and 1 (the --rotate action)."""
    current = read_active_index(state_dir)
    new = 1 - current
    (state_dir / ACTIVE_KEY_FILE).write_text(str(new))
    print(f"rotated active key: {current} -> {new}")


class IdpHandler(BaseHTTPRequestHandler):
    """The four OIDC endpoints. `server.idp` carries the IdpState."""

    # Quieter default request logging (one line per request to stderr).
    def log_message(self, fmt, *log_args):
        sys.stderr.write("fake-idp: " + fmt % log_args + "\n")

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Never cache: rotation must be observed immediately.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server API)
        idp: IdpState = self.server.idp
        url = urllib.parse.urlparse(self.path)
        if url.path == "/.well-known/openid-configuration":
            self._json(
                200,
                {
                    "issuer": idp.issuer,
                    "authorization_endpoint": f"{idp.issuer}/auth",
                    "token_endpoint": f"{idp.issuer}/token",
                    "jwks_uri": f"{idp.issuer}/jwks",
                    "response_types_supported": ["code"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                },
            )
        elif url.path == "/auth":
            query = urllib.parse.parse_qs(url.query)
            state = query.get("state", [None])[0]
            nonce = query.get("nonce", [""])[0]
            client_id = query.get("client_id", [None])[0]
            redirect_uri = query.get("redirect_uri", [None])[0]
            code_challenge = query.get("code_challenge", [None])[0]
            code_challenge_method = query.get("code_challenge_method", [None])[0]
            # Offline access is a policy decision on the ZPR side
            # (`allow_offline_access`), so the refresh token is vended only
            # when the relying party actually asked for the scope. Google's
            # `access_type=offline` is deliberately NOT honored as an
            # alternative: the standard scope is what must work.
            offline = "offline_access" in query.get("scope", [""])[0].split()
            if not state or not redirect_uri or not client_id:
                self._json(400, {"error": "invalid_request"})
                return
            # Only S256 is advertised in discovery; reject anything else so a
            # client silently downgrading PKCE fails loudly here.
            if code_challenge and code_challenge_method != "S256":
                self._json(400, {"error": "invalid_request"})
                return
            # No UI: authorize immediately. Remember the request's bindings
            # so /token can check the exchange against them.
            code = secrets.token_urlsafe(24)
            idp.codes[code] = {
                "nonce": nonce,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "offline": offline,
            }
            sep = "&" if "?" in redirect_uri else "?"
            location = (
                f"{redirect_uri}{sep}code={urllib.parse.quote(code)}"
                f"&state={urllib.parse.quote(state)}"
            )
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif url.path == "/jwks":
            self._json(200, {"keys": [idp.active_key().jwk]})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802 (http.server API)
        idp: IdpState = self.server.idp
        url = urllib.parse.urlparse(self.path)
        if url.path != "/token":
            self._json(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        grant_type = form.get("grant_type", [None])[0]
        if grant_type == "refresh_token":
            self._refresh_grant(idp, form)
            return
        code = form.get("code", [None])[0]
        if grant_type != "authorization_code" or code is None:
            self._json(400, {"error": "invalid_request"})
            return
        # Codes are single use: pop, so a replay is rejected.
        try:
            granted = idp.codes.pop(code)
        except KeyError:
            self._json(400, {"error": "invalid_grant"})
            return
        # The exchange must match the authorization request's bindings
        # (RFC 6749 §4.1.3): same client_id, same redirect_uri. A ph-cli
        # regression sending the wrong values fails here, as Google would
        # fail it.
        if form.get("client_id", [None])[0] != granted["client_id"]:
            self._json(400, {"error": "invalid_client"})
            return
        if form.get("redirect_uri", [None])[0] != granted["redirect_uri"]:
            self._json(400, {"error": "invalid_grant"})
            return
        # PKCE (RFC 7636 §4.6): when the authorization request carried a
        # code_challenge, the token request's code_verifier must S256-hash
        # to it.
        if granted["code_challenge"] is not None:
            verifier = form.get("code_verifier", [None])[0]
            if verifier is None:
                self._json(400, {"error": "invalid_grant"})
                return
            digest = hashlib.sha256(verifier.encode("utf-8")).digest()
            if b64url(digest) != granted["code_challenge"]:
                self._json(400, {"error": "invalid_grant"})
                return
        # This is the interactive login, so `auth_time` is now; every later
        # renewal of this session re-presents exactly this value.
        auth_time = int(time.time())
        id_token, iat = idp.mint_id_token(granted["nonce"], auth_time=auth_time)
        payload = {"id_token": id_token, "token_type": "Bearer", "expires_in": 3600}
        if granted["offline"]:
            refresh_token = secrets.token_urlsafe(32)
            idp.sessions[refresh_token] = {
                "auth_time": auth_time,
                "last_iat": iat,
            }
            payload["refresh_token"] = refresh_token
        self._json(200, payload)

    def _refresh_grant(self, idp: IdpState, form: dict) -> None:
        """`grant_type=refresh_token` (RFC 6749 section 6): renew the
        `id_token` from a stored session.

        The renewed id_token carries NO `nonce` claim, per OIDC Core section
        12.2's SHOULD NOT and matching Google. The visa service's reauth path
        must accept that as readily as a present-and-original one, since it
        performs no nonce check at all; a harness that always echoed the
        claim would not exercise the branch production actually presents.

        The refresh token is deliberately NOT rotated. RFC 6749 section 6
        leaves rotation optional, and a stable token keeps the test's
        revocation leg able to re-present the same value the relying party
        is holding.
        """
        token = form.get("refresh_token", [None])[0]
        if token is None or form.get("client_id", [None])[0] != idp.client_id:
            self._json(400, {"error": "invalid_request"})
            return
        # A revoked grant and an unknown token are the same answer, which is
        # also what makes ph-cli drop its stored token (RFC 6749 section 5.2
        # `invalid_grant`).
        if refresh_revoked(idp.state_dir) or token not in idp.sessions:
            self._json(400, {"error": "invalid_grant"})
            return
        session = idp.sessions[token]
        id_token, iat = idp.mint_id_token(
            None,
            auth_time=session["auth_time"],
            after_iat=session["last_iat"],
        )
        session["last_iat"] = iat
        self._json(200, {"id_token": id_token, "token_type": "Bearer", "expires_in": 3600})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=9000, help="listen port (default 9000)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="IPv4 address to listen on and name in the issuer (default 127.0.0.1); "
        "a LAN address serves a remote node (windows-node-test.md, macos-node-test.md)",
    )
    parser.add_argument(
        "--state-dir",
        required=True,
        help="directory for the rotation state file (shared with --rotate)",
    )
    parser.add_argument("--tls-cert", help="TLS server certificate (PEM)")
    parser.add_argument("--tls-key", help="TLS server private key (PEM)")
    parser.add_argument("--signing-key", help="RSA private key for id_token signing (PEM)")
    parser.add_argument(
        "--signing-key-2",
        help="second RSA signing key, activated by --rotate",
    )
    parser.add_argument("--client-id", default="zpr-test-client", help="expected aud")
    parser.add_argument("--sub", default="fake-idp-user-1", help="sub claim")
    parser.add_argument("--email", default="user1@example.com", help="email claim")
    parser.add_argument("--hd", default="example.com", help="hd (hosted domain) claim")
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="toggle the active signing key of a server sharing --state-dir, then exit",
    )
    parser.add_argument(
        "--revoke-refresh",
        action="store_true",
        help="refuse every later refresh grant of a server sharing --state-dir, then exit",
    )
    parser.add_argument(
        "--print-jwks",
        action="store_true",
        help="print the JWKS for all provided signing keys and exit (seed fixture)",
    )
    args = parser.parse_args()

    if args.rotate:
        rotate(Path(args.state_dir))
        return 0

    if args.revoke_refresh:
        revoke_refresh(Path(args.state_dir))
        return 0

    if not args.signing_key:
        parser.error("--signing-key is required to serve")
    idp = IdpState(args)

    if args.print_jwks:
        print(json.dumps({"keys": [k.jwk for k in idp.keys]}, indent=2))
        return 0

    if not args.tls_cert or not args.tls_key:
        parser.error("--tls-cert and --tls-key are required to serve (issuer is https-only)")

    # Threaded, because a single-threaded HTTPServer serializes EVERYTHING
    # through one loop: a client that stalls mid-TLS-handshake or holds a
    # keep-alive connection open blocks accept() for every later client. In
    # the 2026-09-25 renewal-test run (zipline#104) exactly that made the
    # per-netns instance go deaf after leg 2 — both post-revocation renewals
    # failed on transport ("error sending request") and the revoked grant was
    # never presented.
    #
    # Threading alone is not enough: on a TLS-wrapped LISTENING socket the
    # handshake runs inside accept() — still in the accept loop's thread —
    # so a stalled handshake would wedge the server anyway. The listener
    # therefore stays plaintext and each connection is wrapped in
    # finish_request(), which ThreadingMixIn runs in the per-connection
    # thread; a stuck client rots in its own thread while the accept loop
    # keeps serving. A failed handshake raises there and is reported by
    # handle_error() without killing the server. The shared IdpState is safe
    # enough for a test harness: the mutations are single dict/property
    # operations (atomic under the GIL), and rotation/revocation state is a
    # file re-read per request.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)

    class TlsIdpServer(ThreadingHTTPServer):
        # Do not block exit on a wedged connection thread.
        daemon_threads = True

        def finish_request(self, request, client_address):
            tls_request = context.wrap_socket(request, server_side=True)
            try:
                super().finish_request(tls_request, client_address)
            finally:
                tls_request.close()

    server = TlsIdpServer((args.host, args.port), IdpHandler)
    server.idp = idp
    sys.stderr.write(f"fake-idp: serving {idp.issuer} (kid {idp.active_key().kid})\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
