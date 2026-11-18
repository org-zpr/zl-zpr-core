ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := v4-1node-2actor-ping.bin2 v4-1node-3actor-ping.bin2 v6-1node-2actor-ping.bin2 v6-1node-3actor-ping.bin2 oidc-test.bin2 oidc-renewal.bin2 oidc-file-interplay.bin2 attr-query.bin2 zodes-policy-reauth.bin2 zodes-policy-reauth-no-zb.bin2 zodes-policy-reauth-no-zc.bin2 zodes.bin2 zodes-unlinked.bin2 zodes-pair.bin2 zodes-direct.bin2 zodes-login.bin2 zodes-rejoin.bin2

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean   - removes all the .bin2 policy files
	@echo make all     - recompiles out of date policy files
	@echo make rebuild - run a clean followed by an all.
	@echo
	@echo Requires zplc 0.21.x, the only version the visa service loads.
	@echo Requires that \'zplc\' the ZPL compiler is in your path.
	@echo Or you can set path to zplc by setting ZPLC variable.
	@echo

all: $(OBJS)

clean:
	rm -f $(OBJS)

rebuild: clean all

v6-1node-2actor-ping.bin2: v6-1node-2actor-ping.zplc v4-1node-2actor-ping.zpl
	$(ZPLC) -c v6-1node-2actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-2actor-ping.zpl


v6-1node-3actor-ping.bin2: v6-1node-3actor-ping.zplc v4-1node-3actor-ping.zpl
	$(ZPLC) -c v6-1node-3actor-ping.zplc -k $(KEY) -f v2 -o $@ v4-1node-3actor-ping.zpl


%.bin2: %.zpl %.zplc
	$(ZPLC) -k $(KEY) $<

# OIDC integration-test fixture (zipline#16). Compiled with the same zplc
# vintage as the other fixtures; `service` is deliberately omitted from the
# trusted-service block (no CONNECT proxy in the test), so zplc emits a
# warning — expected, do not add --Werror here.
oidc-test.bin2: oidc-test.zpl oidc-test.zplc oidc-test-seed-jwks.json
	$(ZPLC) -c oidc-test.zplc -k $(KEY) -f v2 -o $@ oidc-test.zpl

# Silent-OIDC-renewal fixture (zipline#47). Deliberately reuses oidc-test.zpl
# verbatim — the ZPL is identical and only the .zplc lifetime knobs differ —
# the same trick v6-1node-2actor-ping.bin2 plays on v4-1node-2actor-ping.zpl
# above. Same omitted-`service` warning as oidc-test; expected.
oidc-renewal.bin2: oidc-renewal.zplc oidc-test.zpl oidc-test-seed-jwks.json
	$(ZPLC) -c oidc-renewal.zplc -k $(KEY) -f v2 -o $@ oidc-test.zpl

# oidc + file interplay fixture (zipline#27). Same fake-IdP pinning as
# oidc-test, plus the happyfile file store from the trusted-service
# interplay plan. Compiling this is itself an acceptance check: the
# `google` service is referenced by no ZPL statement and must survive by
# the identity-vendor retention rule (zipline#23) — zplc >= 0.17.0 with
# that rule prints "trusted service `google` retained: vends identity
# attributes"; an older zplc silently prunes it and the test's zpdump
# check catches the difference.
oidc-file-interplay.bin2: oidc-file-interplay.zpl oidc-file-interplay.zplc oidc-test-seed-jwks.json
	$(ZPLC) -c oidc-file-interplay.zplc -k $(KEY) -f v2 -o $@ oidc-file-interplay.zpl

# oidc + zpr-attr/1 interplay fixture (zipline#81): oidc-file-interplay with
# the file decorator replaced by the networked attribute service, on the
# Zode layout of zodes-pair (zl-zipline#234). Needs a zplc that knows node
# links (feature/zodes) and api = "zpr-attr/1" (zipline#76; an older zplc
# fails with "trusted_service zipline missing provider"). Same omitted-
# `service` warning as oidc-test; expected.
attr-query.bin2: attr-query.zpl attr-query.zplc zb-rsa-pubkey.pem zc-rsa-pubkey.pem oidc-test-seed-jwks.json
	$(ZPLC) -c attr-query.zplc -k $(KEY) -f v2 -o $@ attr-query.zpl

# Fake-IdP signing keys (checked in; test-only, no secrecy requirement) and
# the seed JWKS derived from key 1 only via --print-jwks, which reuses the
# exact JWK construction the server's /jwks endpoint serves, so seed and
# live JWKS cannot drift. Key 2 is deliberately NOT in the seed: after
# --rotate the visa service must observe an unknown kid and refresh from
# the live /jwks, which is the stale-cache path the rotation leg tests.
fake-idp-keys: fake-idp-rsa.key fake-idp-rsa-2.key oidc-test-seed-jwks.json

fake-idp-rsa.key:
	openssl genrsa -out $@ 2048

fake-idp-rsa-2.key:
	openssl genrsa -out $@ 2048

oidc-test-seed-jwks.json: fake-idp-rsa.key
	python3 ../lib/fake-idp.py --state-dir . \
	    --signing-key fake-idp-rsa.key \
	    --print-jwks > $@


.PHONY: all clean rebuild fake-idp-keys

.DEFAULT_GOAL: info

# Zode links fixture (zl-zipline#250): the relay linked to zb, and the same
# without the link. Needs a zplc that knows node links and peer CNs
# (feature/zodes). zb's RSA authentication key is checked in.
zodes.bin2: zodes.zplc zodes.zpl zb-rsa-pubkey.pem
	$(ZPLC) -c zodes.zplc -k $(KEY) -f v2 -o $@ zodes.zpl

zodes-unlinked.bin2: zodes-unlinked.zplc zodes.zpl zb-rsa-pubkey.pem
	$(ZPLC) -c zodes-unlinked.zplc -k $(KEY) -f v2 -o $@ zodes.zpl

# Two-joiner Zode fixtures (zl-zipline#254): the relay linked to zb and zc,
# and the same plus a direct zb-zc link. One ZPL, two configs, the same
# trick v6-1node-2actor-ping.bin2 plays. zc's RSA authentication key is
# checked in, like zb's.
zodes-pair.bin2: zodes-pair.zplc zodes-pair.zpl zb-rsa-pubkey.pem zc-rsa-pubkey.pem
	$(ZPLC) -c zodes-pair.zplc -k $(KEY) -f v2 -o $@ zodes-pair.zpl

zodes-direct.bin2: zodes-direct.zplc zodes-pair.zpl zb-rsa-pubkey.pem zc-rsa-pubkey.pem
	$(ZPLC) -c zodes-direct.zplc -k $(KEY) -f v2 -o $@ zodes-pair.zpl

# Rejoin-after-expiry fixture (zl-zipline#271): zodes-pair plus a UDP/53
# service on zc that needs zb's short-lived `device.hostname` attribute.
zodes-rejoin.bin2: zodes-rejoin.zplc zodes-rejoin.zpl zb-rsa-pubkey.pem zc-rsa-pubkey.pem
	$(ZPLC) -c zodes-rejoin.zplc -k $(KEY) -f v2 -o $@ zodes-rejoin.zpl

# Zode login fixture (zl-zipline#233): zodes.zplc's relay and zb plus the
# fake IdP as an OIDC trusted service, as in oidc-renewal.zplc. Same
# omitted-`service` warning as oidc-test; expected.
zodes-login.bin2: zodes-login.zplc zodes-login.zpl zb-rsa-pubkey.pem oidc-test-seed-jwks.json
	$(ZPLC) -c zodes-login.zplc -k $(KEY) -f v2 -o $@ zodes-login.zpl

# Policy-install re-authentication fixtures for Zodes (zipline#124, ported
# by zl-zipline#234): the relay linked to zb and zc, plus the fake IdP as an
# OIDC trusted service. One ZPL, three configs: the base policy, the same
# without zb's bootstrap key (leg 3), and without zb's and zc's (leg 4), the
# one-source trick zodes-pair.bin2 plays. Same omitted-`service` warning as
# oidc-test; expected.
zodes-policy-reauth.bin2: zodes-policy-reauth.zplc zodes-policy-reauth.zpl zb-rsa-pubkey.pem zc-rsa-pubkey.pem oidc-test-seed-jwks.json
	$(ZPLC) -c zodes-policy-reauth.zplc -k $(KEY) -f v2 -o $@ zodes-policy-reauth.zpl

zodes-policy-reauth-no-zb.bin2: zodes-policy-reauth-no-zb.zplc zodes-policy-reauth.zpl zc-rsa-pubkey.pem oidc-test-seed-jwks.json
	$(ZPLC) -c zodes-policy-reauth-no-zb.zplc -k $(KEY) -f v2 -o $@ zodes-policy-reauth.zpl

zodes-policy-reauth-no-zc.bin2: zodes-policy-reauth-no-zc.zplc zodes-policy-reauth.zpl oidc-test-seed-jwks.json
	$(ZPLC) -c zodes-policy-reauth-no-zc.zplc -k $(KEY) -f v2 -o $@ zodes-policy-reauth.zpl
