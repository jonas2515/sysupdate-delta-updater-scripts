#![allow(non_snake_case)]

use futures::StreamExt;
use libcryptsetup_rs::{
    CryptInit, CryptParamsVerity, CryptParamsVerityRef,
    consts::{flags::CryptVerity, vals::EncryptionFormat},
};
use multipart_async_stream::{
    LendingIterator, MultipartStream, TryStreamExt, header::CONTENT_TYPE,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::min;
use std::error::Error;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::num::ParseIntError;
use std::fs::OpenOptions;
use std::{env, fs::File, io::Read, os::fd::AsRawFd, os::fd::OwnedFd, path::PathBuf, process};
use std::os::fd::RawFd;
use tokio::fs::remove_file;
use uuid::Uuid;
use zlink::{Listener, Reply, ReplyError, unix};
use memfd;

use sysupdate_delta_updater_scripts::delta_manifest;

const N_RANGES_PER_DOWNLOAD: usize = 800;
const SOCKET_PATH: &str = "/run/systemd/io.systemd.PullWorker/https+delta";

fn help() {
    println!(
        "usage: updater_prototype

Spawn a varlink server as the https+delta backend in
/run/systemd/io.systemd.PullWorker/https+delta."
    );
}

fn copy_block(
    mut source: &File,
    source_offset_bytes: usize,
    mut target: &File,
    target_offset_bytes: usize,
) -> Result<(), Box<dyn Error>> {
    source.seek(SeekFrom::Start(source_offset_bytes as u64))?;
    let mut source_take = source.take(delta_manifest::BLOCK_SIZE as u64);

    target.seek(SeekFrom::Start(target_offset_bytes as u64))?;

    std::io::copy(&mut source_take, &mut target)?;

    Ok(())
}

async fn download_and_update_blocks_multirange(
    http_client: &Client,
    mut target_file: &File,
    target_offset_bytes: usize,
    ranges_to_download: &[(usize, u64)],
    url: &str,
) -> Result<(), Box<dyn Error>> {
    // First put together the Range header, it will look something like this:
    // Range: bytes=0-5,40-50
    let mut range_header = "bytes=".to_string();
    for (offset, n_chunks) in ranges_to_download {
        let start_bytes: u64 = *offset as u64 * (delta_manifest::BLOCK_SIZE as u64);
        let end_bytes: u64 = start_bytes + ((delta_manifest::BLOCK_SIZE as u64) * n_chunks) - 1;

        range_header.push_str(&format!("{}-{},", start_bytes, end_bytes));
    }
    // Remove the trailing "," char
    range_header.pop();

    // Fire off the HTTP range request
    let response = http_client.get(url).header("Range", range_header).send().await?;
    if !response.status().is_success() {
        let code = response.status();
        return Err(format!("Delta download failed (HTTP status: {code})").into());
    }

    // Now things are getting fun, parse the Content-Type header from the response ...
    let content_type_header = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());

    // ... and if it's a multi-range header (looking like this
    // `Content-Type: multipart/byteranges; boundary=3d6b6a416f9b5`) ...
    if content_type_header.is_some_and(|h| h.contains("multipart/byteranges")) {
        // ... extract the boundary string (the divider that marks the beginning/end
        // of ranges in the stream) ...
        let boundary_str = content_type_header
            .unwrap()
            .split("boundary=")
            .nth(1)
            .unwrap()
            .trim();
        let boundary_as_u8 = boundary_str.as_bytes().to_vec();

        // ... and pass it to MultipartStream to identify ranges for us.
        let mut ranges_stream = MultipartStream::new(response.bytes_stream(), &*boundary_as_u8);
        let mut ranges_to_download_iter = ranges_to_download.into_iter();

        // Then loop through the ranges we receive and at the same time
        // through the ranges_to_download array (which is supposed to have one
        // entry for each range that we receive, in the same order as well) ...
        while let Some(Ok(part)) = ranges_stream.next().await
            && let Some((range_offset, range_n_chunks)) = ranges_to_download_iter.next()
        {
            let range_offset_bytes = target_offset_bytes + *range_offset * delta_manifest::BLOCK_SIZE;
            let range_size_bytes = *range_n_chunks as usize * delta_manifest::BLOCK_SIZE;

            // ... and for each new range, seek to the offset in our target file ...
            target_file.seek(SeekFrom::Start(range_offset_bytes as u64))?;

            // ... and stream the range into the file bit by bit ...
            let mut range_bytes_downloaded = 0;
            let mut body = part.body();
            while let Ok(Some(b)) = body.try_next().await {
                range_bytes_downloaded += b.len();
                // ... while carefully ensuring that the downloaded range is not
                // larger than it should be.
                if range_bytes_downloaded > range_size_bytes {
                    return Err("Too many bytes received in download".into());
                }

                target_file.write_all(&*b)?;
            }
        }
    // ... if we only requested a single range, we'll get either no Content-Type
    // header or `Content-Type: application/octet-stream` ...
    } else if content_type_header.is_none_or(|h| h == "application/octet-stream") {
        // ... make sure that a single range is actually what we requested ...
        assert!(ranges_to_download.len() == 1);

        let (range_offset, range_n_chunks) = ranges_to_download[0];
        let range_offset_bytes = target_offset_bytes + range_offset * delta_manifest::BLOCK_SIZE;
        let range_size_bytes = range_n_chunks as usize * delta_manifest::BLOCK_SIZE;

        // ... and now stream the range into the file the same way as we do above.
        target_file.seek(SeekFrom::Start(range_offset_bytes as u64))?;

        let mut range_bytes_downloaded = 0;
        let mut stream = response.bytes_stream();
        while let Some(Ok(b)) = stream.next().await {
            range_bytes_downloaded += b.len();
            if range_bytes_downloaded > range_size_bytes {
                return Err("Too many bytes received in download".into());
            }

            target_file.write_all(&*b)?;
        }
    } else {
        return Err("Delta download returned wrong content type".into());
    }

    Ok(())
}

async fn download_and_update_blocks(
    target_file: File,
    target_offset_bytes: usize,
    downloads: Vec<(usize, u64)>,
    url: String,
) -> Result<(), std::io::Error> {
    // FIXME: for some reason the reqwest library sometimes just doesn't send a
    // request over the network. It's consistently the 6th or so request submitted.
    // The problem seems to be specific to some web servers and only to https.
    // A workaround seems to be using the rustls tls implementation (or native?).
    //let client = reqwest::ClientBuilder::new().use_rustls_tls().build().unwrap();
    let client = reqwest::Client::new();

    let mut cur_range = 0;
    while cur_range < downloads.len() {
        let last_range = min(cur_range + N_RANGES_PER_DOWNLOAD, downloads.len());

        if let Err(error) = download_and_update_blocks_multirange(&client, &target_file, target_offset_bytes, &downloads[cur_range..last_range], &url).await
        {
            return Err(std::io::Error::other(format!(
                "Failure to download range: {}",
                error
            )));
        }

        cur_range = cur_range + N_RANGES_PER_DOWNLOAD;
    }

    target_file.sync_data()?;

    Ok(())
}

fn clone_file_for_thread(
    existing_file: &File,
) -> Result<File, std::io::Error> {
    // So apparently if you open() the FD in /proc/self/fd a second time, you can
    // actually write to the file from a second thread and that won't mess with
    // the writes from the existing thread.
    //
    // File.try_clone() doesn't work like that actually and, but if we
    // open() again ourselves, that works fine.
    let target_fd_path = PathBuf::from(format!("/proc/self/fd/{}", existing_file.as_raw_fd()));

    OpenOptions::new().write(true).open(&target_fd_path)
}

async fn update_image_with_block_mapping(
    old_image_file: &File,
    old_image_offset_bytes: usize,
    old_image_size_bytes: usize,
    target_file: &File,
    target_offset_bytes: usize,
    new_image_url: &str,
    new_blocks_to_old_blocks: Vec<u64>,
) -> Result<(), Box<dyn Error>> {
    let mut n_chunks_cur_download = 0;
    let mut begin_block_cur_download = 0;
    let mut ranges_to_download = Vec::new();

    for (target_block_num, source_block_num) in new_blocks_to_old_blocks.iter().enumerate() {
        if *source_block_num == u64::MAX {
            if n_chunks_cur_download == 0 {
                begin_block_cur_download = target_block_num;
                n_chunks_cur_download = 1;
            } else {
                n_chunks_cur_download += 1;
            }
        } else {
            if n_chunks_cur_download > 0 {
                ranges_to_download.push((begin_block_cur_download, n_chunks_cur_download));
                n_chunks_cur_download = 0;
            }
        }
    }

    if n_chunks_cur_download > 0 {
        ranges_to_download.push((begin_block_cur_download, n_chunks_cur_download));
    }

    // As an optimization we start downloading right now in an async task, and
    // copy from the old to the new image at the same time.
    //
    // Also ideally writing downloaded data to disk would not block downloading.
    // For that we trust the kernel to do its caching thing though, it should
    // pretty much do this for us already.
    println!("Now copying unchanged blocks and downloading changed ones");
    let download_task = tokio::task::spawn(download_and_update_blocks(
        clone_file_for_thread(target_file)?,
        target_offset_bytes,
        ranges_to_download.to_vec(),
        new_image_url.to_string(),
    ));

    for (target_block_num, source_block_num) in new_blocks_to_old_blocks.iter().enumerate() {
        if *source_block_num != u64::MAX {
            let source_offset_bytes = old_image_offset_bytes
                + (*source_block_num as usize * delta_manifest::BLOCK_SIZE);
            assert!(
                (source_offset_bytes + delta_manifest::BLOCK_SIZE)
                    <= (old_image_offset_bytes + old_image_size_bytes)
            );

            let copy_target_offset_bytes = target_offset_bytes
                + target_block_num * delta_manifest::BLOCK_SIZE;

            copy_block(
                &old_image_file,
                source_offset_bytes,
                &target_file,
                copy_target_offset_bytes,
            )?;
        }
    }

    download_task.await??;

    // Adrian says we still need to sync the data, even though we read back
    // afterwards (the kernel always lies)
    target_file.sync_data()?;

    Ok(())
}

async fn download_manifest(
    new_image_manifest_url: &str,
) -> Result<delta_manifest::Manifest, Box<dyn Error>> {
    let response = reqwest::get(new_image_manifest_url).await?;
    if !response.status().is_success() {
        return Err("Manifest download failed".into());
    }

    let body_bytes = response.bytes().await?;
    let manifest = delta_manifest::read_manifest_bytes(body_bytes)?;

    Ok(manifest)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn new_sealed_size_memfd(memfd_size_bytes: usize) -> Result<memfd::Memfd, Box<dyn std::error::Error>> {
    let opts = memfd::MemfdOptions::default().allow_sealing(true);
    let mfd = opts.create("memfd-fixed-size-for-dm-verity")?;

    mfd.as_file().set_len(memfd_size_bytes as u64)?;

    mfd.add_seals(&[
        memfd::FileSeal::SealShrink,
        memfd::FileSeal::SealGrow
    ])?;

    mfd.add_seal(memfd::FileSeal::SealSeal)?;

    Ok(mfd)
}

fn create_verity_image(
    data_file: &File,
    data_offset_bytes: usize,
    data_size_bytes: usize,
    verity_fd: RawFd,
    verity_salt: [u8; 32],
) -> Result<[u8; 32], Box<dyn Error>> {
    let data_path = PathBuf::from(format!("/proc/self/fd/{}", data_file.as_raw_fd()));
    let hash_device_path = PathBuf::from(format!("/proc/self/fd/{}", verity_fd));

    // FIXME: currently it's impossible to pass an offset for the data to dm-verity
    assert!(data_offset_bytes == 0);

    let params = CryptParamsVerity {
        hash_name: "sha256".to_string(),
        data_device: data_path,
        hash_device: None,
        fec_device: None,
        salt: Vec::from(verity_salt),
        hash_type: 1,
        data_block_size: 4096, // supposed to be partition sector size
        hash_block_size: 4096, // supposed to be partition sector size
        data_size: data_size_bytes as u64 / 4096, // this is actually the veritysetup --data-blocks option, so it'll be multiplied by data_block_size
        hash_area_offset: 0,
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

    let mut root_hash: [u8; 32] = [0u8; 32];
    let (_key_slot, _key_size) = device.volume_key_handle().get(None, &mut root_hash, None)?;

    Ok(root_hash)
}

fn measure_sha256sum(
    mut image: &File,
    offset: usize,
    size: usize,
) -> Result<[u8; 32], Box<dyn Error>> {
    image.seek(SeekFrom::Start(offset as u64))?;
    let mut source_take = image.take(size as u64);

    let mut hasher = Sha256::new();
    std::io::copy(&mut source_take, &mut hasher)?;

    let result = hasher.finalize();

    return Ok(result[0..32].try_into()?);
}

fn calculate_verity_size(image_size_bytes: usize) -> usize {
    let mut verity_size = 0;

    // verity header + offset until the beginning of data/hash blocks
    verity_size += 4096;

    let data_block_size = 4096;
    let hash_block_size = 4096;
    assert!(image_size_bytes % data_block_size == 0);
    let mut n_data_blocks = image_size_bytes / data_block_size;

    loop {
        // hash blocks are also aligned to be offset at 4096, so need to ceil() them
        verity_size += ((n_data_blocks as f64 * 32_f64) / hash_block_size as f64).ceil() as usize
            * hash_block_size;
        n_data_blocks = (n_data_blocks as f64 / 128_f64).ceil() as usize;
        if n_data_blocks == 1 {
            break;
        }
    }

    return verity_size;
}

fn print_hexarray(string: &str, array: &[u8]) {
    print!("{string}");
    for byte in array {
        print!("{:02x}", byte);
    }
    print!("\n");
}

async fn delta_update_image(
    old_image_fd: OwnedFd,
    old_image_offset_bytes: usize,
    old_image_size_bytes: usize,
    target_fd: OwnedFd,
    target_offset_bytes: usize,
    target_size_bytes: usize,
    checksum: Option<[u8; 32]>,
    new_image_url: &str,
    new_image_manifest_url: &str,
) -> Result<(), Box<dyn Error>> {
    let old_image_file = File::from(old_image_fd);
    let mut target_file = File::from(target_fd);

    println!("Reading old image to get block hashes");
    let old_image_block_hashes = delta_manifest::read_image_block_hashes_from_file(
        &old_image_file,
        old_image_offset_bytes,
        old_image_size_bytes,
    )?;
    let old_image_hashes_to_blocks =
        delta_manifest::hashes_to_blocks_map_from_block_hashes(old_image_block_hashes);

    let new_image_manifest = download_manifest(new_image_manifest_url).await?;
    let new_image_block_hashes = new_image_manifest.block_hashes;

    let (n_blocks_avail_in_old_image, new_blocks_to_old_blocks) =
        delta_manifest::get_new_to_old_block_mapping(
            old_image_hashes_to_blocks,
            new_image_block_hashes,
        );

    let n_blocks_new_image = new_blocks_to_old_blocks.len();
    let new_image_size_bytes = n_blocks_new_image * delta_manifest::BLOCK_SIZE;

    println!(
        "Percentage of blocks avail from existing image: {}",
        n_blocks_avail_in_old_image as f32 / n_blocks_new_image as f32
    );
    println!(
        "Download size: {} MiB",
        ((n_blocks_new_image - n_blocks_avail_in_old_image) * delta_manifest::BLOCK_SIZE)
            / 1024
            / 1024
    );

    let verity_data_size_bytes = calculate_verity_size(new_image_size_bytes);
    let final_size_bytes = new_image_size_bytes + verity_data_size_bytes;
    println!(
        "Final image size will be: {} (image) + {} (verity) = {} bytes",
        new_image_size_bytes, verity_data_size_bytes, final_size_bytes
    );
    if final_size_bytes > target_size_bytes {
        return Err(format!(
            "Final image size will be larger than max size ({target_size_bytes} bytes)"
        )
        .into());
    }

    // Now that we know the final size will not exceed target_size_bytes, we
    // start writing to the target. This means:
    //
    // 1) For copying from the existing image to the target image, we won't exceed
    // it, because that's simply reading the new_blocks_to_old_blocks array, which
    // we just checked in the final_size_bytes check (new_image_size_bytes is derived
    // from new_blocks_to_old_blocks).
    // 2) For the blocks that we download, we create the ranges_to_download array
    // (again by reading the new_blocks_to_old_blocks array) and then make sure the
    // range-downloads don't exceed the size of the ranges in ranges_to_download.
    //
    // -> There's no need to pass target_size_bytes here.
    update_image_with_block_mapping(
        &old_image_file,
        old_image_offset_bytes,
        old_image_size_bytes,
        &target_file,
        target_offset_bytes,
        new_image_url,
        new_blocks_to_old_blocks,
    )
    .await?;

    if checksum.is_some() {
        println!("Now creating and validating checksum of updated image");
    } else {
        println!("Now creating checksum of updated image (without validating)");
    }
    let sha256sum = measure_sha256sum(&target_file, target_offset_bytes, new_image_size_bytes)?;
    if checksum.is_some_and(|c| c != sha256sum) {
        return Err("sha256sum of updated image doesn't match the one we got passed".into());
    }

    // ... 3) For dm-verity we do another special thing: To ensure that dm-verity
    // doesn't misbehave and write more data than what we calculated above, we
    // create a memfd with the calculated verity_data_size_bytes and pass dm-verity
    // the FD to that memfd.
    println!("Now creating new verity data, using image checksum as salt");
    let verity_memfd = new_sealed_size_memfd(verity_data_size_bytes)?;
    let verity_salt = sha256sum;
    let verity_offset_bytes = target_offset_bytes + new_image_size_bytes;

    let root_hash = create_verity_image(
        &target_file,
        target_offset_bytes,
        new_image_size_bytes,
        verity_memfd.as_raw_fd(),
        verity_salt,
    )?;
    print_hexarray("dm-verity root hash: ", &root_hash);

    target_file.seek(SeekFrom::Start(verity_offset_bytes as u64))?;
    std::io::copy(&mut verity_memfd.into_file(), &mut target_file)?;

    Ok(())
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

// Method calls the service handles
#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "parameters")]
enum PullWorkerMethod<'a> {
    #[serde(rename = "io.systemd.PullWorker.Pull")]
    Pull {
        #[allow(unused)]
        version: &'a str,
        #[allow(unused)]
        mode: RemoteType,
        #[allow(unused)]
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

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    //libcryptsetup_rs::set_debug_level(CryptDebugLevel::All);

    remove_file(SOCKET_PATH).await?;
    let mut listener = unix::bind(SOCKET_PATH)?;

    // Wait for someone to connect to the socket
    let connection = listener.accept().await?;
    let (mut read_conn, mut write_conn) = connection.split();

    // Now wait until we receive a method call on the connection
    let (call, mut fds) = read_conn.receive_call::<PullWorkerMethod>().await?;

    let result: Result<(), PullWorkerError> = match call.method() {
        PullWorkerMethod::Pull {
            version: _,
            mode: _,
            fsync: _,
            verify,
            checksum,
            source,
            instances,
            offset,
            maxSize,
            subvolume,
        } => {
            if *verify == ImageVerify::Signature {
                println!("Signature verification is not supported");
                Err(PullWorkerError::InvalidParameters)
            } else if *verify == ImageVerify::Checksum && checksum.is_none() {
                println!("Checksum must be passed when verify is set to checksum");
                Err(PullWorkerError::InvalidParameters)
            } else if *source == "" {
                println!("Source must be passed");
                Err(PullWorkerError::InvalidParameters)
            } else if instances.as_ref().is_none_or(|i| i.len() < 1) {
                println!("At least one instance must be passed");
                Err(PullWorkerError::InvalidParameters)
            } else if offset.is_some_and(|o| o < 0) {
                println!("Offset must be positive number");
                Err(PullWorkerError::InvalidParameters)
            } else if maxSize.is_none_or(|s| s % 4096 != 0 || s < 0) {
                println!("Passed maxSize is not divisible by block size");
                Err(PullWorkerError::InvalidParameters)
            } else if fds.len() != 2 {
                println!("Two FDs must be passed to Pull()");
                Err(PullWorkerError::InvalidParameters)
            } else if subvolume.is_some() {
                println!("subvolume option is not supported");
                Err(PullWorkerError::InvalidParameters)
            } else {
                Ok(())
            }
        }
    };

    match result {
        Err(error) => {
            write_conn.send_error(&error, Vec::new()).await?;
            return Err("".into());
        }
        Ok(()) => {}
    }

    let reply: Result<Reply<()>, PullWorkerError> = match call.method() {
        PullWorkerMethod::Pull {
            version: _,
            mode: _,
            fsync: _,
            verify,
            checksum,
            source,
            instances: _,
            offset,
            maxSize,
            subvolume: _,
        } => {
            let target_fd = fds.remove(0);
            let target_offset_bytes = offset.unwrap_or(0) as usize;
            let target_size_bytes = maxSize.unwrap() as usize;

            if target_offset_bytes != 0 {
                return Err(
                    "Offset in the target image passed, dm-verity can't read data at an offset".into(),
                );
            }

            let old_image_fd = fds.remove(0);
            let old_image_offset_bytes = 0;
            let old_image_size_bytes = 235236236236; //File::open(&old_image_path)?.metadata().unwrap().len() as usize;

            let checksum: Option<[u8; 32]> = if *verify == ImageVerify::Checksum {
                // FIXME: make sure we return a proper error here that's not just ParseIntError
                Some((*decode_hex(checksum.unwrap())?).try_into()?)
            } else {
                None
            };

            delta_update_image(
                old_image_fd,
                old_image_offset_bytes,
                old_image_size_bytes,
                target_fd,
                target_offset_bytes,
                target_size_bytes,
                checksum,
                source,
                &format!("{source}.manifest"),
            )
            .await?;

            Ok(Reply::new(None))
        }
    };

    // Send our method reply or error out over the socket
    match reply {
        Ok(reply) => {
            write_conn.send_reply(&reply, Vec::new()).await?;
            return Ok(());
        }
        Err(error) => {
            write_conn.send_error(&error, Vec::new()).await?;
            return Err("".into());
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => run_server().await,
        _ => {
            help();
            process::exit(1)
        }
    }
}
