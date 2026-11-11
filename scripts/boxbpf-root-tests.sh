#!/usr/bin/env bash
# Runs the box policy engine's root integration tests
# (crates/boxbpf/tests/engine_root_integration.rs).
#
# The tests run as the invoking user, like the daemon does. Each one gets a
# delegated cgroup from systemd and starts the loader as root through
# `sudo -n`, so this needs: passwordless sudo, a systemd host (a user manager,
# or without one the tests ask the system manager), cgroup v2, clang, and
# `ip`, `nsenter` and `unshare` for the network namespace test.
#
# Without BOXBPF_ROOT_TEST set the tests skip, which is what `just test` and
# `just test-ignored` see. Extra arguments go to nextest.
#
# Usage: scripts/boxbpf-root-tests.sh [NEXTEST ARGS...]
set -euo pipefail

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
sudo -n true 2>/dev/null || { echo "these tests need passwordless sudo (sudo -n)" >&2; exit 1; }

BOXBPF_ROOT_TEST=1 cargo nextest run -p boxbpf --locked --run-ignored all --no-tests=fail \
    -E 'binary(/_root_integration$/)' "$@"
