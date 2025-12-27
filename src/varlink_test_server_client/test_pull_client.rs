#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::{env, fs::File, os::fd::OwnedFd, process};
use zlink::{ReplyError, proxy, unix};

const SOCKET_PATH: &str = "/run/pull_worker/pull_worker.varlink";

/// Proxy trait for calling methods on the interface.
#[proxy("io.systemd.PullWorker")]
pub trait PullWorker {
    /// Download from a URL into your system
    async fn pull(
        &mut self,
        version: &str,
        mode: &RemoteType,
        fsync: bool,
        verify: &ImageVerify,
        checksum: Option<&str>,
        source: &str,
        #[zlink(fds)] destination_file_descriptor: Vec<OwnedFd>,
        instances: Option<&[PullInstance]>,
        offset: Option<i64>,
        #[zlink(rename = "maxSize")] max_size: Option<i64>,
        subvolume: Option<bool>,
    ) -> zlink::Result<Result<(), PullWorkerError>>;
}

/// Download mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteType {
    /// Raw binary disk images or files, the former typically in a GPT envelope
    Raw,
    /// A tarball, optionally compressed
    Tar,
}

/// Verification mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImageVerify {
    /// No verification
    No,
    /// Verify that downloads match checksum file (SHA256SUMS), but do not check signature of checksum file
    Checksum,
    /// Verify that downloads match checksum file (SHA256SUMS), and check signature of checksum file.
    Signature,
}

/// Instances to reuse data from for delta-updating
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PullInstance {
    /// Version of the instance
    pub version: String,
    /// Path to the location of the instance on the system
    pub location: String,
}

/// Errors that can occur in this interface.
#[derive(Debug, Clone, PartialEq, ReplyError)]
#[zlink(interface = "io.systemd.PullWorker")]
pub enum PullWorkerError {
    /// A parameter is invalid
    InvalidParameters,
    /// An error occured while pulling the data
    PullError,
}

fn help() {
    println!("usage: test_pull_client <image_to_update> <source_url>

Call the io.systemd.PullWorker.Pull() method via varlink, sending <image_to_update>
as destinationFileDescriptor and <source_url> as source.");
}

async fn call_pull(image_to_update: &str, source_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = unix::connect(SOCKET_PATH).await?;

    let data_file = File::open(image_to_update)?;
    let data_file_fd: OwnedFd = data_file.into();

    let pull_instance = PullInstance {
        version: "v1".to_string(),
        location: "location".to_string(),
    };

    let _result = conn.pull(
        "v2", // version
        &RemoteType::Raw, // mode
        false, // fsync
        &ImageVerify::No, // verify
        Some("checksum"), // checksum
        source_url, // source
        Vec::from([data_file_fd]), // destination_file_descriptor
        Some(&[pull_instance]), // instances
        Some(4096 * 100), // offset
        Some(4096 * 100), // max_size
        None, // subvolume
    ).await?.unwrap();

    println!("Successfully called Pull()");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        3 => {
            let image_to_update = &args[1];
            let source_url = &args[2];

            call_pull(image_to_update, source_url).await
        },
        _ => {
            help();
            process::exit(1)
        }
    }
}
