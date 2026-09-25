# COPR "make srpm" entry point (see docs/COPR.md). COPR runs it as root in a
# Fedora chroot with network access:
#   make -f .copr/Makefile srpm outdir=DIR
# It builds the source RPM with packaging/build-rpm.sh, which vendors the Rust
# crates and fetches the face models, so the binary build runs offline.

top := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
spec := $(top)/packaging/peekin.spec
version = $(shell sed -n 's/^Version:[[:space:]]*//p' $(spec))
outdir ?= $(top)/target/copr

srpm:
	if [ "$$(id -u)" = 0 ]; then \
		dnf -y install cargo curl rpm-build rust-srpm-macros systemd-rpm-macros tar gzip findutils; \
	fi
	SRPM_ONLY=1 $(top)/packaging/build-rpm.sh
	mkdir -p "$(outdir)"
	cp $(top)/target/rpmbuild/SRPMS/peekin-$(version)-*.src.rpm "$(outdir)"/

.PHONY: srpm
