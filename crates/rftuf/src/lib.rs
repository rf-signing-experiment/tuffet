//! A client library for [The Update Framework (TUF)](https://theupdateframework.io/),
//! following version 1.0 of the [specification](https://theupdateframework.github.io/specification/latest/).
//!
//! TUF secures software update systems: it lets a client verify that the
//! files it downloads from a repository are the ones the repository's
//! (offline, threshold-protected) keys vouch for, and that it is not being
//! shown stale, mixed-up or rolled-back metadata.
//!
//! # Layers
//!
//! - [`Updater`] runs the complete client workflow: it fetches metadata
//!   through a [`Transport`](transport::Transport), verifies and persists it
//!   in a [`MetadataStore`](store::MetadataStore), looks up targets through
//!   delegations, and downloads and verifies target files.
//! - [`TrustedMetadata`] implements the workflow's verification rules with
//!   no I/O at all, for callers that want to fetch and store files
//!   themselves. [`TargetSearch`](trusted::TargetSearch) does the same for
//!   delegation lookups.
//! - [`metadata`] holds the metadata types, and signs and verifies
//!   individual metadata files. It is also the API for creating metadata.
//!
//! Supporting modules: [`pouf`] defines the metadata wire format (JSON with
//! canonical-JSON signatures by default), [`crypto`] contains every
//! cryptographic operation behind a backend-neutral API, and [`transport`]
//! and [`store`] define the I/O traits with filesystem and in-memory
//! implementations. There is no built-in HTTP client; see the `rftuf-http`
//! crate, or implement [`Transport`](transport::Transport) yourself.
//!
//! # Example
//!
//! ```no_run
//! use rftuf::store::FilesystemStore;
//! use rftuf::transport::FilesystemTransport;
//! use rftuf::Updater;
//!
//! # async fn example() -> rftuf::Result<()> {
//! let transport = FilesystemTransport::new("/mnt/repo/metadata", "/mnt/repo/targets");
//! let store = FilesystemStore::new("/var/lib/app/tuf")?;
//! let mut updater = Updater::builder(transport, store)
//!     .initial_root(std::fs::read("/usr/share/app/root.json")?)
//!     .build()?;
//!
//! updater.refresh().await?;
//! match updater.get_target_info("app-1.2.tar.gz").await? {
//!     Some(target) => {
//!         let data = updater.download_target(&target).await?;
//!         println!("downloaded {} verified bytes", data.len());
//!     }
//!     None => println!("no such target"),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Scope
//!
//! Multi-repository consensus (TAP 4) and the optional mirrors role are not
//! supported; mirrors metadata in root is preserved but ignored.
//!
//! # Key IDs
//!
//! The specification requires clients to check that every key ID is the hash
//! of its key. Like the reference implementation (python-tuf) and go-tuf,
//! this crate does not: widely deployed repositories, Sigstore's among them,
//! list keys under IDs that were assigned before fields were added to the
//! keys. What the check protects against, one key counting several times
//! towards a signature threshold, is prevented directly instead: thresholds
//! count distinct keys, compared by key material, and each role's signatures
//! are only checked against the keys its delegating role lists.

pub mod crypto;
mod error;
pub mod metadata;
mod paths;
pub mod pouf;
pub mod store;
pub mod transport;
pub mod trusted;
pub mod updater;

pub use error::{Error, Result};
pub use trusted::{TargetInfo, TrustedMetadata};
pub use updater::{Updater, UpdaterConfig};
