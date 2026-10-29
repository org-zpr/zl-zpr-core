# Manual OIDC release checklist — real Google (zipline#16, zipline#40)

CI (the fake-IdP `one-node-oidc-test.sh` and
`one-node-oidc-renewal-test.sh`) cannot cover real Google. Before an
OIDC release is called done, run this checklist once against a real Google
Workspace and record the outcome on the umbrella issue
([org-zpr/zl-zipline#1](https://github.com/org-zpr/zl-zipline/issues/1)).
The `hd`-absent case in particular is the one a fake IdP is most likely to
model wrongly (docs/OIDC.md, "What CI cannot cover").

## Prerequisites

- [ ] A Google Cloud project with an OAuth 2.0 **Desktop app** client
      (loopback redirect; ph-cli binds `http://127.0.0.1:<port>/callback`).
- [ ] A real Google **Workspace** domain and a test account in it
      (`<user>@<workspace-domain>`).
- [ ] A **consumer** Gmail account (`...@gmail.com`) for the rejection case.
- [ ] A policy whose trusted service declares:
      `api = "oidc"`, `issuer = "https://accounts.google.com"`,
      `jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"`,
      the Desktop client's `client_id`,
      `allowed_domains = ["<workspace-domain>"]`,
      `identity_attributes = ["sub"]`, and a seed JWKS snapshot of Google's
      current keys.
- [ ] A running ZPRnet (node, visa service with that policy, one adapter
      with **no** `--bootstrap-key` so authentication is forced through
      OIDC).

## 1. Workspace happy path

- [ ] `ph-cli connect <link>` opens a browser to a Google login.
- [ ] Log in as the Workspace test account; consent; the browser lands on
      the "you can close this window" page.
- [ ] `connect` exits 0 and the link reaches Active; ping across the TUN
      succeeds.
- [ ] The visa service log shows the user admitted with identity `sub` and
      `user.domain = <workspace-domain>` (from `hd`), and **no** log line
      anywhere contains the `id_token`, the authorization code, or the PKCE
      verifier.

## 2. Consumer gmail must be rejected — via `hd` absence

The security requirement (docs/OIDC.md "Security requirements"): match on
`hd`, never on the email domain. A consumer account's token simply has **no
`hd` claim**, and that absence must fail the domain check even if the
account's email address is made to look corporate.

- [ ] Repeat the login as the consumer Gmail account.
- [ ] `connect` fails (exit 5, visa service rejected the token) and the visa
      service reports the domain check failing with the `hd`-absent reason
      ("hd claim absent (consumer account?)").
- [ ] Confirm the rejection is `hd`-based, not email-based: the log must not
      reference the account's email domain in the decision.

## 3. `client_secret` — required for Google Desktop clients, or not?

Google's native-app documentation marks `client_secret` *optional* and
exempts only Android/iOS/Chrome clients, not Desktop (zl-zpr-dev-context/docs/OIDC.md,
"Design decisions"). The implementation carries an **optional,
non-secret** `client_secret` end to end; this run settles whether Google's
token endpoint actually demands it for a Desktop client.

- [ ] Run the happy path **without** `client_secret` in policy. Record:
      token exchange succeeded / failed with `invalid_client`.
- [ ] If it failed: add the Desktop client's `client_secret` to the trusted
      service, re-run, confirm success.
- [ ] **Record the outcome here and on zipline#1:**

      client_secret required for Google Desktop client: YES / NO (fill in)

## 4. No offline access (`allow_offline_access = false`, the default)

The runs above use the default policy, so they double as this case: no
refresh token exists, and a user authentication lasts `expiration_seconds`
from login with no silent renewal.

- [ ] The authorization URL from the runs above carries **no**
      `offline_access` scope and no `access_type=offline`, `prompt=consent`
      or `max_age` parameters.
- [ ] Leave a `ph-cli auth-agent <link>` login up past `expiration_seconds`
      (set it short, e.g. 600, for this run). No browser opens, and the
      node's renewal attempt cannot succeed without a refresh token:
      `ph-cli show-link <link>`'s `Auth expires:` never advances, the visa
      service's authentication-expiry sweep disconnects the actor at
      expiry, and traffic across the TUN stops.

## 5. Silent renewal against Google (`allow_offline_access = true`)

What this section settles is **Google's** behaviour on the renewal path,
which the fake IdP only models (docs/OIDC.md, "Credential lifetimes and
re-authentication"). It is not a test of the renewal loop itself, so run
`one-node-oidc-renewal-test.sh` green against the fake IdP **first**. Its
banner records that it has not yet been observed passing; if it fails,
stop here and fix that, since a failure below would be uninterpretable.

Policy for this run, on the Google trusted service:
`allow_offline_access = true`, `expiration_seconds = 600`,
`max_auth_age_seconds = 1800`. (The compiler requires
`max_auth_age_seconds > 0` with offline access, and
`max_auth_age_seconds >= expiration_seconds`.) With the node's default
300 s renewal lead, renewals fall due about every 5 minutes, and the
session ceiling lands 30 minutes after login.

- [ ] Run `ph-cli auth-agent <link>` and **leave it running**: renewal
      only happens while the agent is alive, so `connect` cannot be used
      here. The authorization URL carries `offline_access` in `scope`, plus
      `access_type=offline`, `prompt=consent` and `max_age=31536000`.
- [ ] **Record whether Google accepts that request:** accepted / rejected
      with `invalid_scope` (or another error). If rejected, file an issue
      against `ph-cli`'s authorization request with the exact error, and
      stop this section.
- [ ] The login completes and the visa service admits the user. A
      rejection for a missing `auth_time` means Google ignored `max_age`.
      **Record:** `auth_time` present in the login `id_token`: YES / NO.
- [ ] Wait for the first renewal (about 5 minutes). **No browser opens**,
      the visa service logs `re-authorizing ... (proven session renewal)`,
      `ph-cli show-link <link>` reports a later `Auth expires:` than
      before, and ping across the TUN keeps working.
- [ ] If the renewal is rejected instead (`reauthorize failed for actor
      ...` in the visa service log), record the reason verbatim. The
      likeliest real-Google divergence is the refreshed `id_token` itself:
      the visa service requires the same `sub`, a strictly later `iat`, an
      **unchanged** `auth_time`, and `hd` still present. **Record:**
      Google's refreshed `id_token` carries `auth_time`: YES / NO.
- [ ] Let several renewals pass silently, then confirm the session
      ceiling. At about 30 minutes after login, renewal can no longer move
      the expiry forward. The visa service's authentication-expiry sweep
      disconnects the actor, and traffic stops. Getting back on needs a
      fresh interactive login.
- [ ] Revocation: in the Google account's security settings, remove the
      application's access while an agent is logged in. The next renewal
      fails (`invalid_grant`), and the actor is disconnected at its
      current expiry, not at the ceiling.
- [ ] Throughout, no log line anywhere contains the refresh token, an
      `id_token` or an authorization code.

## Recording

Close-out is the operator's step: after one full run, record the outcomes
(sections 1–5, including the recorded YES / NO answers) in a comment on
[zipline#1](https://github.com/org-zpr/zl-zipline/issues/1) for sections
1–4 and on [zipline#40](https://github.com/org-zpr/zl-zipline/issues/40)
for section 5.
