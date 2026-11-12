ZPLC ?= zplc
KEY := zpr-rsa-key.pem

OBJS := v4-1node-2actor-ping.bin2 v4-1node-3actor-ping.bin2 v6-1node-2actor-ping.bin2 v6-1node-3actor-ping.bin2 oidc-test.bin2 oidc-renewal.bin2 oidc-file-interplay.bin2 attr-query.bin2 policy-reauth.bin2 policy-reauth-no-adapter2.bin2 policy-reauth-no-node.bin2 zodes.bin2

info:
	@echo Makefile to help with compiling the ZPR policies
	@echo from source.
	@echo
	@echo make clean   - removes all the .bin2 policy files
	@echo make all     - recompiles out of date policy files
	@echo make rebuild - run a clean followed by an all.
	@echo
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

# Policy-install re-authentication fixtures (zipline#124). One ZPL, three
# configs: the base policy plus two variants whose only difference is a
# removed [bootstrap] key (adapter2's for leg 3, the node's for leg 4) —
# the same one-source trick oidc-renewal.bin2 plays on oidc-test.zpl. Same
# omitted-`service` warning as oidc-test; expected. Needs zplc >= 0.20.0
# (the policy version the visa service accepts, zipline#114).
policy-reauth.bin2: policy-reauth.zplc policy-reauth.zpl oidc-test-seed-jwks.json
	$(ZPLC) -c policy-reauth.zplc -k $(KEY) -f v2 -o $@ policy-reauth.zpl

policy-reauth-no-adapter2.bin2: policy-reauth-no-adapter2.zplc policy-reauth.zpl oidc-test-seed-jwks.json
	$(ZPLC) -c policy-reauth-no-adapter2.zplc -k $(KEY) -f v2 -o $@ policy-reauth.zpl

policy-reauth-no-node.bin2: policy-reauth-no-node.zplc policy-reauth.zpl oidc-test-seed-jwks.json
	$(ZPLC) -c policy-reauth-no-node.zplc -k $(KEY) -f v2 -o $@ policy-reauth.zpl

# oidc + zpr-attr/1 interplay fixture (zipline#81): oidc-file-interplay with
# the file decorator replaced by the networked attribute service. Needs
# zplc >= 0.19.0 (zipline#76: api = "zpr-attr/1" parsing) — an older zplc
# fails with "trusted_service zipline missing provider". Same omitted-
# `service` warning as oidc-test; expected.
attr-query.bin2: attr-query.zpl attr-query.zplc oidc-test-seed-jwks.json
	$(ZPLC) -c attr-query.zplc -k $(KEY) -f v2 -o $@ attr-query.zpl

# Zode netns fixture (zl-zipline#222): a relay docking the visa service and
# two joining Zodes, used by the zode-*-test.sh scripts. `transit` needs
# zplc >= the zl-zipline#226 compiler (feature/zodes); an older zplc
# rejects or ignores it. The zb/zc RSA authentication keys are checked in
# (test-only); the relay reuses node-rsa-key.pem.
zodes.bin2: zodes.zplc zodes.zpl zb-rsa-pubkey.pem zc-rsa-pubkey.pem
	$(ZPLC) -c zodes.zplc -k $(KEY) -f v2 -o $@ zodes.zpl

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
