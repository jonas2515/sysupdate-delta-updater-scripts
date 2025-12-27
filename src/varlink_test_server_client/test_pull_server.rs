#![allow(non_snake_case)]

use libcryptsetup_rs::{
    CryptInit, CryptParamsVerity, CryptParamsVerityRef,
    consts::{flags::CryptVerity, vals::CryptDebugLevel, vals::EncryptionFormat},
};
use serde::{Deserialize, Serialize};
use std::{env, fs::File, io, io::Read, os::fd::IntoRawFd, path::PathBuf, process};
use uuid::Uuid;
use zlink::{Listener, Reply, ReplyError, unix};

const SOCKET_PATH: &str = "/run/pull_worker/pull_worker.varlink";

// To test running the thing with minimal permissions, copy it to /opt/, then run with systemd-run
// sudo systemd-run -p ProtectSystem=strict -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p ReadOnlyPaths=/ -p DynamicUser=yes -p ProtectHome=yes -p PrivateTmp=yes -p PrivateMounts=yes -p PrivateDevices=yes -p PrivateUsers=yes -p RuntimeDirectory=pull_worker/ -p RestrictAddressFamilies="AF_UNIX" -p IPAddressDeny=any -p PrivateNetwork=yes -p ProtectHostname=yes -p ProtectClock=yes -p ProtectKernelModules=yes  -p ProtectKernelLogs=yes  -p ProtectControlGroups=yes  -p RestrictNamespaces=yes -p LockPersonality=yes -p MemoryDenyWriteExecute=yes -p RestrictRealtime=yes -p RestrictSUIDSGID=yes -p RemoveIPC=yes -p SystemCallFilter= -p SystemCallFilter="~@clock @module @mount @obsolete @raw-io @reboot @resources @swap @privileged @debug" -p SystemCallArchitectures=native -p SystemCallErrorNumber=EPERM -p ProtectKernelTunables=yes -p ProtectProc=invisible -p ProcSubset=pid -p UMask=0000 --wait -v /opt/test_pull_server

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

// Method calls the service handles
#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
enum PullWorkerMethod<'a> {
    #[serde(rename = "io.systemd.PullWorker.Pull")]
    Pull {
        version: &'a str,
        mode: RemoteType,
        fsync: bool,
        verify: ImageVerify,
        checksum: Option<&'a str>,
        source: &'a str,
        instances: Option<Vec<PullInstance>>,
        offset: Option<i64>,
        maxSize: Option<i64>,
        subvolume: Option<bool>,
    },
}

fn generate_salt() -> Result<[u8; 32], io::Error> {
    // read 32 bytes from /dev/random to get a salt
    let mut rng = File::open("/dev/random")?;

    let mut salt = [0u8; 32];
    rng.read_exact(&mut salt)?;

    Ok(salt)
}

fn help() {
    println!(
        "usage: test_pull_server

Spawn a io.systemd.PullWorker varlink server that creates dm-verity data for an
image (using an offset for the verity data) passed via io.systemd.PullWorker.Pull()
method."
    );
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    libcryptsetup_rs::set_debug_level(CryptDebugLevel::All);

    let mut listener = unix::bind(SOCKET_PATH)?;

    // Wait for someone to connect to the socket
    let connection = listener.accept().await?;
    let (mut read_conn, mut write_conn) = connection.split();

    // Now wait until we receive a method call on the connection
    let (call, mut fds) = read_conn.receive_call::<PullWorkerMethod>().await?;

    let reply: Result<Reply<()>, PullWorkerError> = match call.method() {
        PullWorkerMethod::Pull {
            version,
            mode,
            fsync,
            verify,
            checksum,
            source,
            instances,
            offset,
            #[allow(non_snake_case)]
            maxSize,
            subvolume,
        } => {
            println!(
                "Pull() method call version={}, mode={:?}, fsync={}, verify={:?}, checksum={:?}, source={}, instances={:?}, offset={:?}, maxSize={:?}, subvolume={:?}",
                version,
                mode,
                fsync,
                verify,
                checksum,
                source,
                instances,
                offset,
                maxSize,
                subvolume
            );

            if offset.is_none_or(|o| o < 0) {
                println!("Passing offset is required");
                Err(PullWorkerError::InvalidParameters)
            } else if maxSize.is_none_or(|s| s % 4096 != 0 || s < 0) {
                println!("Passed maxSize is not divisible by block size");
                Err(PullWorkerError::InvalidParameters)
            } else if fds.len() != 1 {
                println!("A single FD must be passed to Pull()");
                Err(PullWorkerError::InvalidParameters)
            } else {
                let destination_fd = fds.pop().unwrap().into_raw_fd();
                let destination_path = PathBuf::from(&format!("/proc/self/fd/{destination_fd}"));
                let hash_device_path = destination_path.clone();

                let params = CryptParamsVerity {
                    hash_name: "sha256".to_string(),
                    data_device: destination_path,
                    hash_device: None,
                    fec_device: None,
                    salt: Vec::from(generate_salt()?),
                    hash_type: 1,
                    data_block_size: 4096, // supposed to be partition sector size
                    hash_block_size: 4096, // supposed to be partition sector size
                    data_size: maxSize.unwrap() as u64 / 4096, // this is actually the veritysetup --data-blocks option, so it'll be multiplied by data_block_size
                    hash_area_offset: offset.unwrap() as u64,
                    fec_area_offset: 0,
                    fec_roots: 0,
                    flags: CryptVerity::CREATE_HASH,
                };

                let mut params_ref: CryptParamsVerityRef = (&params).try_into()?;
                let mut device = CryptInit::init(&hash_device_path)?;
                device.context_handle().format::<CryptParamsVerityRef>(
                    EncryptionFormat::Verity,
                    ("", ""),                            // cipher and mode
                    Some(Uuid::new_v4()),                // verity partition uuid
                    libcryptsetup_rs::Either::Left(&[]), // volume key
                    Some(&mut params_ref),
                )?;

                println!("aslihgislaghisg");
                Ok(Reply::new(None))
            }
        }
    };

    // Send our method reply or error out over the socket
    match reply {
        Ok(reply) => {
            write_conn.send_reply(&reply, Vec::new()).await?;
        }
        Err(error) => {
            write_conn.send_error(&error, Vec::new()).await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => run_server().await,
        _ => {
            help();
            process::exit(1)
        }
    }
}
