# rftuf

A Rust client library for [The Update Framework (TUF)](https://theupdateframework.io/),
implementing the client workflow of the specification in [`tuf-spec.md`](tuf-spec.md)
(version 1.0.36).

| Crate | Purpose |
| --- | --- |
| [`rftuf`](crates/rftuf/src/) | The library. No HTTP client; filesystem and in-memory I/O are built in. |
| [`rftuf-http`](crates/rftuf-http/) | An HTTP(S) `Transport` built on reqwest. |
| [`rftuf-conformance`](crates/conformance/) | The client-under-test for the [tuf-conformance] test suite (not published). |

## Layers

**`Updater`**: runs the whole client workflow. It fetches metadata through a
`Transport`, verifies it, persists it in a `MetadataStore`, follows
delegations to find targets, and downloads and verifies target files.

```rust
let transport = HttpTransport::new(metadata_url, targets_url); // or FilesystemTransport, MemoryTransport
let store = FilesystemStore::new("/var/lib/app/tuf")?;          // or MemoryStore
let mut updater = Updater::builder(transport, store)
    .initial_root(std::fs::read("/usr/share/app/root.json")?)
    .build()?;

updater.refresh().await?;
if let Some(target) = updater.get_target_info("app-1.2.tar.gz").await? {
    updater.download_target_to(&target, Path::new("app-1.2.tar.gz")).await?;
}
```

**`trusted::TrustedMetadata`**: every verification rule of the client workflow
(signatures and thresholds, root chaining, rollback, freeze and mix-and-match
checks), with no I/O. You feed it bytes in workflow order and it accepts or
rejects them. `trusted::TargetSearch` is the delegation search, also without
I/O. Use these to drive the workflow with your own networking and storage.

**`metadata`**: the role payloads (`Root`, `Timestamp`, `Snapshot`, `Targets`),
the signed envelope `Metadata<T>`, and signing and verification of single
files. It is also the API for creating metadata (see
[`tests/support/repo.rs`](crates/rftuf/tests/support/repo.rs) for a small repository built with it).

## Design notes

- **POUF.** The wire format is a `pouf::Pouf` type parameter that defaults to
  `pouf::Json`: JSON signed over OLPC canonical JSON, compatible with
  python-tuf. Signatures are checked against the canonical form of the
  payload exactly as received, so fields this crate doesn't know are covered
  by signatures and preserved on re-encoding.
- **Cryptography** lives entirely in [`src/crypto`](crates/rftuf/src/crypto/). The
  backend-neutral part holds the TUF rules (schemes, key encodings, RSA key
  sizes, the message ML-DSA signs); a backend supplies the primitives (see
  [Features](#features)). Supported schemes: `ed25519`,
  `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`,
  `rsassa-pss-sha256`/`-sha384`/`-sha512` (RSA keys of 2048 to 8192 bits)
  and the post-quantum `ml-dsa-44/1`/`-65/1`/`-87/1` of [TAP 21]. Custom signers
  (HSM, KMS) implement `crypto::Signer`, and `crypto::public_key_from_spki`
  (or `_from_pem`) turns their public keys into metadata `Key`s.
- **I/O** is defined by two traits: `transport::Transport` (async; returns
  streams so the library can enforce size limits while downloading) and
  `store::MetadataStore`. The library is runtime-agnostic.
- **Path patterns** in delegations follow glob(7), the shell convention the
  specification refers to. Each `/`-separated segment is matched with the
  `glob` crate (as python-tuf and go-tuf match segment by segment), so that
  wildcards never match a `/`; see [`pattern.rs`](crates/rftuf/src/metadata/pattern.rs).
- **Key IDs** are treated as opaque labels, as python-tuf and go-tuf do, rather
  than being recomputed as the specification requires; see the crate docs.
- **Not supported:** multi-repository consensus (TAP 4) and the mirrors role.

## Features

| Crate | Feature | Effect |
| --- | --- | --- |
| `rftuf` | `rustcrypto` (default) | Cryptography from the RustCrypto crates ([`rustcrypto.rs`](crates/rftuf/src/crypto/rustcrypto.rs)). |
| `rftuf` | `aws-lc-rs` | Cryptography from AWS-LC ([`aws_lc.rs`](crates/rftuf/src/crypto/aws_lc.rs)). Takes precedence over `rustcrypto`; disable default features to leave RustCrypto out. Enable `aws-lc-rs/fips` in your own manifest for FIPS mode. |
| `rftuf-http` | `rustls` (default), `native-tls` | TLS implementation of the default HTTP client. |
| `rftuf-http` | `rustcrypto` (default), `aws-lc-rs` | Passed through to `rftuf`. With `rustls`, `aws-lc-rs` means a single crypto library. |

The backends behave the same, with two exceptions:

- The `aws-lc-rs` backend only verifies RSA-PSS signatures whose salt is as
  long as the digest, because `aws-lc-rs` offers no other option. That is the
  length python-tuf, go-tuf and this crate sign with; the `rustcrypto` backend
  also accepts other lengths.
- The `rustcrypto` backend only loads ML-DSA private keys that include the
  seed (OpenSSL's default form and the seed-only form); `aws-lc-rs` also loads
  keys that hold just the expanded key.

## Dependencies to know about

`rsa` is pinned to `0.10.0-rc.18`. The stable 0.9 line has an open timing
advisory (RUSTSEC-2023-0071) and can't auto-detect PSS salt lengths, which
interoperability needs. The other RustCrypto crates (ed25519-dalek 3, p256/p384
0.14, sha2 0.11) are stable releases of the same generation. ML-DSA comes from
`ml-dsa` 0.1, which has not been independently audited; use the `aws-lc-rs`
backend if that matters for your post-quantum keys.

## Testing

```sh
cargo test --workspace                                    # rustcrypto backend
cargo test -p rftuf --no-default-features -F aws-lc-rs    # aws-lc-rs backend
cargo test -p rftuf --all-features                        # also compares the two backends
```

The tests are organized by section of the specification, so that each
requirement can be checked against the tests that enforce it. See
[`tests/README.md`](crates/rftuf/tests/README.md) for the strategy, the layout, and the
attacks each test detects.

- [`tests/workflow`](crates/rftuf/tests/workflow/): the client workflow (section 5), step
  by step, against generated repositories.
- [`tests/metadata`](crates/rftuf/tests/metadata/): the metadata formats (section 4),
  with snapshots of the encoding of each role.
- [`tests/crypto`](crates/rftuf/tests/crypto/): key types and signature schemes, against
  OpenSSL-made keys and signatures.
- [`tests/io`](crates/rftuf/tests/io/) and [`tests/interop.rs`](crates/rftuf/tests/interop.rs): the
  built-in transports and stores, and python-tuf's test repository (updated
  from on disk here, and over HTTP in `rftuf-http`).

### Conformance

The [tuf-conformance] suite tests the client against the specification and
other implementations' behavior. rftuf passes all its tests; tests expected to
fail would be listed in
[`crates/conformance/rftuf-conformance.xfails`](crates/conformance/rftuf-conformance.xfails).
To run it locally (needs git, Python 3.10+ and `faketime`):

```sh
conformance/run.sh                          # extra arguments go to pytest, e.g. -k NAME -rA
BACKEND=aws-lc-rs conformance/run.sh
```
