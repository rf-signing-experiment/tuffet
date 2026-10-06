//! Tests against a local HTTP server.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use chrono::{TimeZone, Utc};
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rftuf::store::{MemoryStore, MetadataStore};
use rftuf::transport::{Transport, TransportError};
use rftuf::{Error, Updater};
use rftuf_http::HttpTransport;
use tokio::net::TcpListener;

/// A server for `files` (by URL path). `/status/N` responds with status N
/// and `/endless` with a body that never ends. Returns its address and a log
/// of the requested paths.
async fn serve(files: HashMap<String, Vec<u8>>) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let files = Arc::new(files);
    let log = Arc::new(Mutex::new(Vec::new()));
    let server_log = log.clone();
    tokio::spawn(async move {
        loop {
            let (connection, _) = listener.accept().await.unwrap();
            let (files, log) = (files.clone(), server_log.clone());
            let service = service_fn(move |request: Request<Incoming>| {
                let path = request.uri().path().to_owned();
                log.lock().unwrap().push(path.clone());
                let response = respond(&files, &path);
                async move { Ok::<_, Infallible>(response) }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(connection), service)
                    .await;
            });
        }
    });
    (address, log)
}

fn respond(files: &HashMap<String, Vec<u8>>, path: &str) -> Response<BoxBody<Bytes, Infallible>> {
    let full = |status: StatusCode, body: Vec<u8>| {
        let mut response = Response::new(Full::new(Bytes::from(body)).boxed());
        *response.status_mut() = status;
        response
    };
    if let Some(code) = path.strip_prefix("/status/") {
        return full(
            StatusCode::from_u16(code.parse().unwrap()).unwrap(),
            Vec::new(),
        );
    }
    if path == "/endless" {
        let chunks = std::iter::repeat_with(|| Ok(Frame::data(Bytes::from_static(&[b'x'; 1024]))));
        return Response::new(StreamBody::new(futures_util::stream::iter(chunks)).boxed());
    }
    match files.get(path) {
        Some(body) => full(StatusCode::OK, body.clone()),
        None => full(StatusCode::NOT_FOUND, Vec::new()),
    }
}

fn transport(address: SocketAddr) -> HttpTransport {
    HttpTransport::new(
        format!("http://{address}/metadata/").parse().unwrap(),
        format!("http://{address}/targets/").parse().unwrap(),
    )
}

#[tokio::test]
async fn fetches_files_and_maps_status_codes() {
    let files = HashMap::from([
        ("/metadata/timestamp.json".to_owned(), b"timestamp".to_vec()),
        (
            "/targets/dir/a%20file%3F.txt".to_owned(),
            b"target".to_vec(),
        ),
    ]);
    let (address, log) = serve(files).await;
    let transport = transport(address);

    let read = |stream: rftuf::transport::ByteStream| async {
        stream
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
            .unwrap()
    };
    assert_eq!(
        read(transport.fetch_metadata("timestamp.json").await.unwrap()).await,
        b"timestamp"
    );
    assert_eq!(
        read(transport.fetch_target("dir/a file?.txt").await.unwrap()).await,
        b"target"
    );
    assert_eq!(log.lock().unwrap()[1], "/targets/dir/a%20file%3F.txt");

    assert!(matches!(
        transport.fetch_metadata("2.root.json").await,
        Err(TransportError::NotFound(name)) if name == "2.root.json"
    ));
    // Fetching "N" below `/status/` responds with status N.
    let status = HttpTransport::new(
        format!("http://{address}/status/").parse().unwrap(),
        format!("http://{address}/status/").parse().unwrap(),
    );
    assert!(matches!(
        status.fetch_metadata("403").await,
        Err(TransportError::NotFound(_))
    ));
    assert!(matches!(
        status.fetch_target("500").await,
        Err(TransportError::Other { .. })
    ));
}

#[tokio::test]
async fn endless_responses_are_cut_off() {
    let (address, _) = serve(HashMap::new()).await;
    let transport = HttpTransport::new(
        format!("http://{address}/").parse().unwrap(),
        format!("http://{address}/").parse().unwrap(),
    );
    let mut stream = transport.fetch_target("endless").await.unwrap();
    let mut received = 0;
    while received < 1_000_000 {
        received += stream.try_next().await.unwrap().unwrap().len();
    }
    // Reaching here means the body was streamed rather than buffered.
}

#[tokio::test]
async fn updates_from_the_reference_implementations_repository_over_http() {
    let data = Path::new(env!("CARGO_MANIFEST_DIR")).join("../rftuf/tests/data/python-tuf");
    let mut files = HashMap::new();
    for (dir, prefix) in [("metadata", "/metadata/"), ("targets", "/targets/")] {
        for entry in std::fs::read_dir(data.join(dir)).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            files.insert(
                format!("{prefix}{name}"),
                std::fs::read(entry.path()).unwrap(),
            );
        }
    }
    let (address, log) = serve(files).await;

    let store = Arc::new(MemoryStore::new());
    let mut updater = Updater::builder(transport(address), store.clone())
        .initial_root(std::fs::read(data.join("metadata/root.json")).unwrap())
        .build()
        .unwrap();
    updater
        .refresh_at(Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap())
        .await
        .unwrap();

    let target = updater.get_target_info("file3.txt").await.unwrap().unwrap();
    assert_eq!(target.role, "role1");
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("file3.txt");
    updater
        .download_target_to(&target, &destination)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(destination).unwrap(),
        std::fs::read(data.join("targets/file3.txt")).unwrap()
    );

    assert_eq!(
        *log.lock().unwrap(),
        [
            "/metadata/2.root.json",
            "/metadata/timestamp.json",
            "/metadata/snapshot.json",
            "/metadata/targets.json",
            "/metadata/role1.json",
            "/targets/file3.txt",
        ]
    );
    assert!(store.load("role1.json").unwrap().is_some());

    // A tampered target is rejected.
    let missing = updater.get_target_info("file4.txt").await.unwrap();
    assert!(missing.is_none());
    let mut forged = target.clone();
    forged.file.length -= 1;
    assert!(matches!(
        updater.download_target(&forged).await,
        Err(Error::TooLarge { .. })
    ));
}
