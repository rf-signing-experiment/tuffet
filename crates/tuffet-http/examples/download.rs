//! Securely downloads a target file from a TUF repository over HTTP.
//!
//! ```text
//! cargo run -p tuffet-http --example download -- \
//!     <metadata-url> <targets-url> <trusted-root.json> <cache-dir> <target-path> <output-file>
//! ```
//!
//! `cache-dir` keeps the trusted metadata between runs; use one per repository.

use tuffet::Updater;
use tuffet::store::FilesystemStore;
use tuffet_http::HttpTransport;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [metadata_url, targets_url, root, cache_dir, target, output] = args.as_slice() else {
        eprintln!(
            "usage: download <metadata-url> <targets-url> <trusted-root.json> <cache-dir> <target-path> <output-file>"
        );
        std::process::exit(2);
    };

    let transport = HttpTransport::new(metadata_url.parse()?, targets_url.parse()?);
    let mut updater = Updater::builder(transport, FilesystemStore::new(cache_dir)?)
        .initial_root(std::fs::read(root)?)
        .build()?;

    updater.refresh().await?;
    let trusted = updater.trusted().expect("refreshed");
    println!(
        "trusted metadata: root v{}, timestamp v{}, snapshot v{}",
        trusted.root().signed().version,
        trusted.timestamp().expect("loaded").signed().version,
        trusted.snapshot().expect("loaded").signed().version,
    );

    let Some(info) = updater.get_target_info(target).await? else {
        return Err(format!("{target} is not a trusted target").into());
    };
    updater.download_target_to(&info, output.as_ref()).await?;
    println!(
        "downloaded {target} ({} bytes, listed by role {:?}) to {output}",
        info.file.length, info.role
    );
    Ok(())
}
