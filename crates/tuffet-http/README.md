# tuffet-http

An HTTPS `Transport` for the [`tuffet`](https://crates.io/crates/tuffet) client
for [The Update Framework (TUF)](https://theupdateframework.io/), built on
[reqwest](https://crates.io/crates/reqwest).

```rust
let transport = HttpTransport::new(metadata_url, targets_url);
let mut updater = Updater::builder(transport, FilesystemStore::new("./tuf/")?)
    .initial_root(std::fs::read("root.json")?)
    .build()?;
updater.refresh().await?;
```

## Features

Each feature picks both the TLS implementation and `tuffet`'s cryptography
backend:

- `aws-lc-rs` (default): rustls for TLS and AWS-LC for TUF, so AWS-LC is the
  only crypto library.
- `native-tls`: the platform's TLS (OpenSSL, SChannel or Security.framework)
  and RustCrypto for TUF.

To choose them separately, disable the default features and enable reqwest's
TLS feature and `tuffet`'s backend in your own manifest.
With both features, `tuffet` uses AWS-LC and reqwest's default client uses
native-tls.

See the [tuffet repository](https://github.com/rf-signing-experiment/tuffet) for
more.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
