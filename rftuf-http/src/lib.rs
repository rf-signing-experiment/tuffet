//! An HTTP(S) [`Transport`] for the [`rftuf`] TUF client, built on
//! [`reqwest`].
//!
//! ```no_run
//! use rftuf::Updater;
//! use rftuf::store::FilesystemStore;
//! use rftuf_http::HttpTransport;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let transport = HttpTransport::new(
//!     "https://tuf.example.com/metadata/".parse()?,
//!     "https://tuf.example.com/targets/".parse()?,
//! );
//! let mut updater = Updater::builder(transport, FilesystemStore::new("/var/lib/app/tuf")?)
//!     .initial_root(std::fs::read("/usr/share/app/root.json")?)
//!     .build()?;
//! updater.refresh().await?;
//! # Ok(())
//! # }
//! ```
//!
//! TLS is optional for TUF's security, but protects the privacy of what is
//! downloaded. The `rustls` (default) and `native-tls` features select the
//! TLS implementation of the default client; pass your own client to
//! [`HttpTransport::with_client`] to configure timeouts, proxies or trusted
//! certificates.

use futures_util::{StreamExt, TryStreamExt, stream};
use reqwest::StatusCode;
use rftuf::transport::{ByteStream, Transport, TransportError};

pub use reqwest;
pub use url::Url;

/// Fetches repository files over HTTP(S).
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
    metadata_url: Url,
    targets_url: Url,
}

impl HttpTransport {
    /// Fetches metadata from below `metadata_url` and targets from below
    /// `targets_url`, using a default client.
    pub fn new(metadata_url: Url, targets_url: Url) -> Self {
        Self::with_client(reqwest::Client::new(), metadata_url, targets_url)
    }

    /// Like [`new`](Self::new), using `client` for all requests.
    pub fn with_client(client: reqwest::Client, metadata_url: Url, targets_url: Url) -> Self {
        HttpTransport {
            client,
            metadata_url,
            targets_url,
        }
    }

    async fn get(&self, url: Url, name: &str) -> Result<ByteStream, TransportError> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| TransportError::other(name, error))?;
        if matches!(
            response.status(),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN
        ) {
            return Err(TransportError::NotFound(name.to_owned()));
        }
        let response = response
            .error_for_status()
            .map_err(|error| TransportError::other(name, error))?;

        let name = name.to_owned();
        let body = stream::try_unfold(response, |mut response| async move {
            Ok(response.chunk().await?.map(|chunk| (chunk, response)))
        })
        .map_err(move |error: reqwest::Error| TransportError::other(name.clone(), error));
        Ok(body.boxed())
    }
}

impl Transport for HttpTransport {
    async fn fetch_metadata(&self, name: &str) -> Result<ByteStream, TransportError> {
        let url = metadata_url(&self.metadata_url, name)
            .map_err(|reason| TransportError::other(name, reason))?;
        self.get(url, name).await
    }

    async fn fetch_target(&self, path: &str) -> Result<ByteStream, TransportError> {
        let url = target_url(&self.targets_url, path)
            .map_err(|reason| TransportError::other(path, reason))?;
        self.get(url, path).await
    }
}

/// Appends a metadata file name to `base`. The name is already a single,
/// percent-encoded path segment (see [`Transport::fetch_metadata`]), so it
/// is appended as is.
fn metadata_url(base: &Url, name: &str) -> Result<Url, &'static str> {
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) {
        return Err("invalid metadata file name");
    }
    if base.cannot_be_a_base() {
        return Err("base URL cannot have a path");
    }
    let mut url = base.clone();
    url.set_path(&format!("{}/{name}", base.path().trim_end_matches('/')));
    Ok(url)
}

/// Appends a target path to `base`, percent-encoding each segment so that
/// characters like `?`, `#` and `%` cannot change the meaning of the URL.
fn target_url(base: &Url, path: &str) -> Result<Url, &'static str> {
    let mut url = base.clone();
    let mut segments = url
        .path_segments_mut()
        .map_err(|()| "base URL cannot have a path")?;
    segments.pop_if_empty();
    for segment in path.split('/') {
        if segment == "." || segment == ".." {
            return Err("target path segments must not be `.` or `..`");
        }
        segments.push(segment);
    }
    drop(segments);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(text: &str) -> Url {
        text.parse().unwrap()
    }

    #[test]
    fn appends_below_the_base_with_or_without_trailing_slash() {
        for base in ["https://example.com/repo/", "https://example.com/repo"] {
            assert_eq!(
                metadata_url(&url(base), "1.root.json").unwrap().as_str(),
                "https://example.com/repo/1.root.json"
            );
            assert_eq!(
                target_url(&url(base), "dir/file.tgz").unwrap().as_str(),
                "https://example.com/repo/dir/file.tgz"
            );
        }
        assert_eq!(
            metadata_url(&url("https://example.com"), "timestamp.json")
                .unwrap()
                .as_str(),
            "https://example.com/timestamp.json"
        );
    }

    #[test]
    fn keeps_metadata_names_as_encoded() {
        assert_eq!(
            metadata_url(&url("https://example.com/metadata/"), "team%2Fweb.json")
                .unwrap()
                .as_str(),
            "https://example.com/metadata/team%2Fweb.json"
        );
        assert!(metadata_url(&url("https://example.com/"), "../root.json").is_err());
        assert!(metadata_url(&url("https://example.com/"), "..").is_err());
    }

    #[test]
    fn encodes_target_paths() {
        assert_eq!(
            target_url(&url("https://example.com/targets/"), "a b/c?d#e%f")
                .unwrap()
                .as_str(),
            "https://example.com/targets/a%20b/c%3Fd%23e%25f"
        );
        assert!(target_url(&url("https://example.com/targets/"), "../secret").is_err());
        assert!(target_url(&url("https://example.com/targets/"), "a/./b").is_err());
        assert!(target_url(&url("mailto:someone@example.com"), "x").is_err());
    }
}
