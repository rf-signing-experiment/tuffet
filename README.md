# rftuf

A Rust client library for [The Update Framework (TUF)](https://theupdateframework.io/),
implementing the client workflow of the specification in [`tuf-spec.md`](tuf-spec.md)
(version 1.0.36).

| Crate | Purpose |
| --- | --- |
| [`rftuf`](src/) | The library. No HTTP client; filesystem and in-memory I/O are built in. |
| [`rftuf-http`](rftuf-http/) | An HTTP(S) `Transport` built on reqwest. |

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
[`tests/common/mod.rs`](tests/common/mod.rs) for a small repository built with it).

## Design notes

- **POUF.** The wire format is a `pouf::Pouf` type parameter that defaults to
  `pouf::Json`: JSON signed over OLPC canonical JSON, compatible with
  python-tuf. Signatures are checked against the canonical form of the
  payload exactly as received, so fields this crate doesn't know are covered
  by signatures and preserved on re-encoding.
- **Cryptography** lives entirely in [`src/crypto`](src/crypto/), behind a
  backend-neutral API, and is implemented with RustCrypto crates in
  [`rustcrypto.rs`](src/crypto/rustcrypto.rs) (the default `rustcrypto`
  feature). Supported schemes: `ed25519`, `ecdsa-sha2-nistp256`,
  `ecdsa-sha2-nistp384` and `rsassa-pss-sha256` (RSA keys of 2048 bits or
  more; any PSS salt length). Custom signers (HSM, KMS) implement
  `crypto::Signer`.
- **I/O** is defined by two traits: `transport::Transport` (async; returns
  streams so the library can enforce size limits while downloading) and
  `store::MetadataStore`. The library is runtime-agnostic.
- **Key IDs** are treated as opaque labels, as python-tuf and go-tuf do, rather
  than being recomputed as the specification requires; see the crate docs.
- **Not supported:** multi-repository consensus (TAP 4) and the mirrors role.

## Dependencies to know about

`rsa` is pinned to `0.10.0-rc.18`. The stable 0.9 line has an open timing
advisory (RUSTSEC-2023-0071) and can't auto-detect PSS salt lengths, which
interoperability needs. The other RustCrypto crates (ed25519-dalek 3, p256/p384
0.14, sha2 0.11) are stable releases of the same generation.

## Testing

```sh
cargo test --workspace
```

Besides unit tests, the suite includes:

- [`tests/trusted.rs`](tests/trusted.rs): the verification rules, attack by attack.
- [`tests/updater.rs`](tests/updater.rs): end-to-end updates against generated
  repositories (root rotation, fast-forward recovery, delegations, consistent
  snapshots, tampered targets).
- Interoperability fixtures in [`tests/data`](tests/data/): python-tuf's test
  repository (verified, and updated from on disk and over HTTP) and
  OpenSSL-made keys and signatures.

To try a live repository, run the example. For instance, against Sigstore,
with a root obtained out of band:

```sh
cargo run -p rftuf-http --example download -- \
    https://tuf-repo-cdn.sigstore.dev/ https://tuf-repo-cdn.sigstore.dev/targets/ \
    root.json ./tuf-cache trusted_root.json trusted_root.json
```
