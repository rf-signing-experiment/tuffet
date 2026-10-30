#!/usr/bin/env bash
# Runs the tuf-conformance test suite against tuffet's client-under-test.
#
#   crates/conformance/run.sh [pytest arguments]
#
# For example, `crates/conformance/run.sh -k test_unsigned_metadata -rA` runs a single
# test and shows the client's output. Set BACKEND=aws-lc-rs to test the
# aws-lc-rs crypto backend. Requires git, python3 (3.10 or later) and faketime.
# CI runs this script for both backends (.github/workflows/ci.yml).
set -euo pipefail

TUF_CONFORMANCE_VERSION=v2.5.0
BACKEND=${BACKEND:-rustcrypto}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

if ! command -v faketime >/dev/null; then
    echo "error: faketime is required (Debian/Ubuntu: apt install faketime)" >&2
    exit 1
fi

target_dir=$(cargo metadata --manifest-path "$repo/Cargo.toml" --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
work=$target_dir/tuf-conformance
suite=$work/$TUF_CONFORMANCE_VERSION

# Install the test suite and its Python dependencies, once per version.
if [[ ! -x $suite/env/bin/pytest ]]; then
    rm -rf "$suite"
    git clone --quiet --depth 1 --branch "$TUF_CONFORMANCE_VERSION" \
        https://github.com/theupdateframework/tuf-conformance "$suite"
    python3 -m venv "$suite/env"
    "$suite/env/bin/pip" install --quiet -e "$suite"
fi

cargo build --manifest-path "$repo/Cargo.toml" -p tuffet-conformance \
    --no-default-features --features "$BACKEND"

# The suite reads expected failures from "<client>.xfails".
cp "$target_dir/debug/tuffet-conformance" "$work/tuffet-conformance"
cp "$repo/crates/conformance/tuffet-conformance.xfails" "$work/tuffet-conformance.xfails"

exec "$suite/env/bin/pytest" "$suite/tuf_conformance" --entrypoint "$work/tuffet-conformance" "$@"
