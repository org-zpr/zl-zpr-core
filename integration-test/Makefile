# Run the integration tests inside a throwaway Docker container.
#
# The scripts run their network namespaces and TUN devices inside an
# unprivileged user namespace (`unshare -nr`), so on a host that allows
# unprivileged user namespaces they need no sudo and can be run directly.
# Where that is blocked (and the sysctl cannot be changed), run them as
# root in a container instead:
#
#   make docker-test                      # every *-test.sh (see TESTS), PASS/FAIL summary
#   make docker-test TEST=zode-ping-test.sh
#   make docker-test TEST=zode-ping-test.sh DEBUG_TARGETS="all=INFO zdp=DEBUG"
#   make docker-shell                     # root shell in this directory
#
# Host prerequisites: Docker running and the caller in the `docker` group.
# The binaries are still built on the host (`make` in the repo root, plus the
# vs / vs-admin / zpr-attr-server / zpdump symlinks next to the scripts) and
# are bind-mounted into the container, not built inside it.

IMAGE      ?= zpr-integration-test
BASE_IMAGE ?= ubuntu:26.04

# The vs, vs-admin, zpdump, ... symlinks point into sibling repositories two
# levels up, so mount the whole workspace at the same absolute path and they
# resolve unchanged inside the container.
WORKSPACE  := $(abspath $(CURDIR)/../..)

# ponytail: --privileged covers CAP_SYS_ADMIN/CAP_NET_ADMIN for netns, /dev/net/tun,
# and io_uring (blocked by Docker's default seccomp profile) in one flag.  Narrow it
# to --cap-add/--device/--security-opt only if this ever has to run untrusted code.
DOCKER_TTY :=
DOCKER_RUN  = docker run --rm --privileged $(DOCKER_TTY) $(DOCKER_ENV) \
                -v $(WORKSPACE):$(WORKSPACE) -w $(CURDIR) $(IMAGE)

# a2a-pubkey-test.sh needs a ph built with --features enable-security-testing
# and bails out otherwise, so it is not in the default set; run it explicitly
# with TEST=a2a-pubkey-test.sh against such a build.
TESTS := $(filter-out a2a-pubkey-test.sh,$(sort $(wildcard *-test.sh)))

# The scripts' own overrides (DEBUG_TARGETS, NETEM_PARAMS, PH_BIN, ...) are
# read from the environment, which `docker run` does not inherit.  Forward each
# one that is actually set -- in the environment or on the make command line --
# with a bare `-e NAME`, which copies the caller's value in.  Unset ones are not
# mentioned at all, so the image's own ENV (USER, VALKEY_SERVER_BIN, ...) stands.
FORWARD_ENV := DEBUG_TARGETS KM_IMPL NETEM_PARAMS NODE_AUTH_PRIVATE_KEY FAKE_IDP_PORT \
               SKIP_NOTIFY ZPR_TEST_VERBOSE PH_DEBUG_BUILD \
               PH_BIN PH_DEBUG_BIN VS_BIN VS_ADMIN_BIN ZPR_ATTR_SERVER_BIN ZPDUMP_BIN VALKEY_SERVER_BIN
DOCKER_ENV := $(foreach v,$(FORWARD_ENV),$(if $(filter undefined,$(origin $(v))),,-e $(v)))

.PHONY: docker-image docker-test docker-shell

docker-image:
	docker build --build-arg BASE_IMAGE=$(BASE_IMAGE) -t $(IMAGE) .

# TEST=<script> [args] runs one script; otherwise run them all, keep going past
# failures, print a summary, and exit non-zero if any failed.
docker-test: docker-image
ifdef TEST
	$(DOCKER_RUN) ./$(TEST)
else
	$(DOCKER_RUN) bash -c ' \
	  rc=0; summary=$$(mktemp); \
	  for t in $(TESTS); do \
	    echo "==== $$t ===="; \
	    if ./$$t; then echo "PASS  $$t" >> "$$summary"; \
	    else rc=1; echo "FAIL  $$t" >> "$$summary"; fi; \
	  done; \
	  echo; echo "==== summary ===="; cat "$$summary"; exit $$rc'
endif

docker-shell: DOCKER_TTY := -it
docker-shell: docker-image
	$(DOCKER_RUN) bash
