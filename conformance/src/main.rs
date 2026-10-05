//! The client-under-test for the [tuf-conformance] test suite.
//!
//! Implements the suite's [CLI protocol] on top of [`rftuf::Updater`]. To run
//! the suite, see `conformance/run.sh`.
//!
//! [tuf-conformance]: https://github.com/theupdateframework/tuf-conformance
//! [CLI protocol]: https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use rftuf::Updater;
use rftuf::store::FilesystemStore;
use rftuf_http::{HttpTransport, Url, reqwest};

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

/// Characters escaped when a target path is used as a file name: all but
/// letters, digits, `-` and `_`, so that no name is special (like `..`).
const FILE_NAME: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_');

#[derive(Parser)]
#[command(about = "Client-under-test for the tuf-conformance test suite")]
struct Cli {
    /// Directory holding the trusted metadata.
    #[arg(long)]
    metadata_dir: PathBuf,
    /// Base URL of the repository's metadata.
    #[arg(long)]
    metadata_url: Option<Url>,
    /// Path of a target to download. May be repeated.
    #[arg(long = "target-name")]
    target_names: Vec<String>,
    /// Directory to store downloaded targets in.
    #[arg(long)]
    target_dir: Option<PathBuf>,
    /// Base URL of the repository's targets.
    #[arg(long)]
    target_base_url: Option<Url>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Trust the given root metadata.
    Init { trusted_root: PathBuf },
    /// Update the trusted metadata from the repository.
    Refresh,
    /// Update the trusted metadata, then download the targets.
    Download,
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info,rftuf=debug"))
        .init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let mut message = error.to_string();
            let mut source = error.source();
            while let Some(cause) = source {
                message.push_str(&format!(": {cause}"));
                source = cause.source();
            }
            eprintln!("rftuf-conformance: {message}");
            ExitCode::FAILURE
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { trusted_root } => {
            std::fs::copy(trusted_root, cli.metadata_dir.join("root.json"))?;
        }
        Command::Refresh => {
            let metadata_url = required(cli.metadata_url, "--metadata-url")?;
            // Refreshing fetches no targets, so any targets URL will do.
            let targets_url = metadata_url.clone();
            updater(&cli.metadata_dir, metadata_url, targets_url)?
                .refresh()
                .await?;
        }
        Command::Download => {
            let metadata_url = required(cli.metadata_url, "--metadata-url")?;
            let targets_url = required(cli.target_base_url, "--target-base-url")?;
            let target_dir = required(cli.target_dir, "--target-dir")?;
            let mut updater = updater(&cli.metadata_dir, metadata_url, targets_url)?;
            updater.refresh().await?;
            for name in &cli.target_names {
                let target = updater
                    .get_target_info(name)
                    .await?
                    .ok_or_else(|| format!("no trusted target {name:?}"))?;
                let path = target_dir.join(utf8_percent_encode(name, FILE_NAME).to_string());
                if target.matches_file(&path)? {
                    log::info!("{name} is already downloaded");
                } else {
                    updater.download_target_to(&target, &path).await?;
                }
            }
        }
    }
    Ok(())
}

fn updater(
    metadata_dir: &Path,
    metadata_url: Url,
    targets_url: Url,
) -> Result<Updater<HttpTransport, FilesystemStore>> {
    // The test suite's repository runs on localhost, so bypass any proxy.
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(30))
        .build()?;
    let transport = HttpTransport::with_client(client, metadata_url, targets_url);
    Ok(Updater::builder(transport, FilesystemStore::new(metadata_dir)?).build()?)
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T> {
    value.ok_or_else(|| format!("{flag} is required").into())
}
