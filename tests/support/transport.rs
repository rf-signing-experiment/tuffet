//! A transport that records requests and can simulate failures.

use std::collections::HashSet;
use std::sync::Mutex;

use rftuf::transport::{ByteStream, MemoryTransport, Transport, TransportError};

/// A [`MemoryTransport`] that records what is fetched.
#[derive(Default)]
pub struct RecordingTransport {
    /// The files served.
    pub inner: MemoryTransport,
    requests: Mutex<Vec<String>>,
    failing: Mutex<HashSet<String>>,
}

impl RecordingTransport {
    /// The requests made since the last call, as the metadata file name or
    /// as `target:PATH` for target files.
    pub fn take_requests(&self) -> Vec<String> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }

    /// Makes requests for `request` (named as in
    /// [`take_requests`](Self::take_requests)) fail with an error other than
    /// "not found", as a network failure would.
    pub fn fail(&self, request: &str) {
        self.failing.lock().unwrap().insert(request.to_owned());
    }

    fn record(&self, request: String) -> Result<(), TransportError> {
        let failing = self.failing.lock().unwrap().contains(&request);
        self.requests.lock().unwrap().push(request.clone());
        if failing {
            return Err(TransportError::other(request, "simulated network failure"));
        }
        Ok(())
    }
}

impl Transport for RecordingTransport {
    async fn fetch_metadata(&self, name: &str) -> Result<ByteStream, TransportError> {
        self.record(name.to_owned())?;
        self.inner.fetch_metadata(name).await
    }

    async fn fetch_target(&self, path: &str) -> Result<ByteStream, TransportError> {
        self.record(format!("target:{path}"))?;
        self.inner.fetch_target(path).await
    }
}
