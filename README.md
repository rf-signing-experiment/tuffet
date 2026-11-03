# tuffet

A Rust client library for [The Update Framework (TUF)](https://theupdateframework.io/),
implementing the client workflow of the specification in [`tuf-spec.md`](tuf-spec.md)
(version 1.0.36).

This library is interoperable with other TUF implementations, including: `go-tuf`
`python-tuf`, `sigstore-tuf` and `tuf-on-ci`.

| Crate | Purpose |
| --- | --- |
| [`tuffet`](crates/tuffet/src/) | The library. No HTTP client; filesystem and in-memory I/O are built in. |
| [`tuffet-http`](crates/tuffet-http/) | An HTTP(S) `Transport` built on reqwest. |
| [`tuffet-conformance`](crates/conformance/) | The client-under-test for the [tuf-conformance] test suite (not published). |

## API Layers

**`Updater`**: runs the whole client workflow. It fetches metadata through a
`Transport`, verifies it using `TrustedMetadata`, persists it in a `MetadataStore`,
follows delegations to find targets, and downloads and verifies target files.

```rust
let transport = HttpTransport::new(metadata_url, targets_url);
let store = FilesystemStore::new("./tuf/")?; // or MemoryStore to not persist.
let mut updater = Updater::builder(transport, store)
    .initial_root(std::fs::read("root.json")?)
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
[`tests/support/repo.rs`](crates/tuffet/tests/support/repo.rs) for a small repository built with it).

## Design notes

- **Trust anchor.** The root passed to `initial_root`, normally shipped with
  the application, is the trust anchor.
- **POUF.** The wire format is a `pouf::Pouf` type parameter that defaults to
  `pouf::Json`. Implementing custom POUFs is possible with the `Pouf` trait.
- **Cryptography** lives entirely in [`src/crypto`](crates/tuffet/src/crypto/). The
  backend-neutral part holds the TUF rules (schemes, key encodings, RSA key
  sizes, the message ML-DSA signs). Supported signature schemes, as `keytype`
  and `scheme` in metadata:

  - Ed25519: `ed25519` with `ed25519`. Public keys are hex.
  - ECDSA: `ecdsa` with `ecdsa-sha2-nistp256`, or `ecdsa-sha2-nistp384`.
    Signatures are DER.
  - RSA: `rsa` with `rsassa-pss-sha256`, or `rsassa-pss-sha384` or
    `rsassa-pss-sha512`. Keys must be 2048 to 8192 bits. The `aws-lc-rs`
    backend only verifies signatures whose salt is as long as the digest.
  - ML-DSA ([TAP 21](https://github.com/theupdateframework/taps/blob/master/tap21.md)):
    `ml-dsa` with `ml-dsa-44/1`, `ml-dsa-65/1` or `ml-dsa-87/1`. The
    `rustcrypto` backend only loads private keys that include the seed.

  Public keys other than Ed25519 ones are PEM-encoded `SubjectPublicKeyInfo`.
  The supported file hashes are `sha256` and `sha512`. AWS-LC and RustCrypto
  backends are both supported, controlled by [features](#features).
- **I/O** is defined by two traits: `transport::Transport` (async; returns
  streams so the library can enforce size limits while downloading) and
  `store::MetadataStore`. The library is runtime-agnostic.
- **Path patterns** in delegations follow glob(7), the shell convention the
  specification refers to. Each `/`-separated segment is matched with the
  `glob` crate. Note: wildcards never match a `/`.
- **Key IDs** are treated as opaque labels, as python-tuf and go-tuf do, rather
  than being recomputed as the specification requires; see the crate docs.
- **Not supported:** multi-repository consensus (TAP 4) and the mirrors role.

## Features

| Feature | Effect |
| --- | --- |
| `rustcrypto` (default) | Cryptography from the RustCrypto crates ([`rustcrypto.rs`](crates/tuffet/src/crypto/rustcrypto.rs)). |
| `aws-lc-rs` | Cryptography from AWS-LC ([`aws_lc.rs`](crates/tuffet/src/crypto/aws_lc.rs)). Takes precedence over `rustcrypto` if both are enabled. Use `default-features = false` avoid building RustCrypto. |

## Testing

```sh
cargo test --workspace --no-default-features -F rustcrypto,native-tls  # rustcrypto backend
cargo test --workspace --no-default-features -F aws-lc-rs              # aws-lc-rs backend
```

### TUF Conformance Testing

The tuf-conformance suite tests the client against the specification and
other implementations' behavior. tuffet passes all its tests.
To run it locally (needs git, Python 3.10+ and `faketime`):

```sh
crates/conformance/run.sh
BACKEND=aws-lc-rs crates/conformance/run.sh
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/license/mit>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
