#!/usr/bin/env bash
# Runs the tuf-conformance test suite against rftuf's client-under-test.
#
#   conformance/run.sh [pytest arguments]
#
# For example, `conformance/run.sh -k test_unsigned_metadata -rA` runs a single
# test and shows the client's output. Set BACKEND=aws-lc-rs to test the
# aws-lc-rs crypto backend. Requires git, python3 (3.10 or later) and faketime.
set -euo pipefail

# Keep in sync with the tuf-conformance action in .github/workflows/ci.yml.
TUF_CONFORMANCE_VERSION=v2.5.0
BACKEND=${BACKEND:-rustcrypto}

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

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

cargo build --manifest-path "$repo/Cargo.toml" -p rftuf-conformance \
    --no-default-features --features "$BACKEND"

# The suite reads expected failures from "<client>.xfails".
cp "$target_dir/debug/rftuf-conformance" "$work/rftuf-conformance"
cp "$repo/conformance/rftuf-conformance.xfails" "$work/rftuf-conformance.xfails"

exec "$suite/env/bin/pytest" "$suite/tuf_conformance" --entrypoint "$work/rftuf-conformance" "$@"
