use bytes::Bytes;
use crc_fast::{CrcAlgorithm::Crc64Nvme, checksum};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::io::{Read, Seek};
use std::process::Command;
use zvariant::{LE, Type, as_value, serialized::Context, serialized::Data, signature, to_bytes};

pub const BLOCK_SIZE: usize = 4096;

use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Type, Eq, Serialize, Deserialize)]
#[zvariant(signature = "a{sv}")]
pub struct Manifest {
    #[serde(with = "as_value")]
    pub block_hashes: Vec<u64>,
}

pub fn read_manifest(manifest_filename: &str) -> Result<Manifest, Box<dyn Error>> {
    let serialize_context = Context::new_gvariant(LE, 0);

    let bytes = std::fs::read(manifest_filename)?;
    let bytes = Data::new(bytes, serialize_context);

    let (manifest, _) = bytes.deserialize()?;

    Ok(manifest)
}

pub fn read_manifest_bytes(manifest_bytes: Bytes) -> Result<Manifest, Box<dyn Error>> {
    let serialize_context = Context::new_gvariant(LE, 0);

    let bytes = Data::new(&*manifest_bytes, serialize_context);

    let (manifest, _) = bytes.deserialize()?;

    Ok(manifest)
}

pub fn read_image_block_hashes(filename: &str) -> Result<Vec<u64>, io::Error> {
    let mut image = File::open(filename)?;
    let mut buffer = [0; BLOCK_SIZE];
    let mut total_bytes_read = 0;
    let mut blocks_to_hashes = Vec::new();

    loop {
        let bytes_read = image.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        total_bytes_read += bytes_read;

        let block_hash = checksum(Crc64Nvme, &buffer[..bytes_read]);
        blocks_to_hashes.push(block_hash);

        if total_bytes_read % (1024 * 1024 * 100) == 0 {
            println!(
                "status: read {} MiB of file={}",
                total_bytes_read / (1024 * 1024),
                filename
            );
        }
    }

    println!(
        "Finished reading: file={}, total_bytes_read={} MiB",
        filename,
        total_bytes_read / (1024 * 1024)
    );

    Ok(blocks_to_hashes)
}

pub fn read_image_block_hashes_from_file(
    mut image: &File,
    offset: usize,
    size: usize,
) -> Result<Vec<u64>, io::Error> {
    let mut buffer = [0; BLOCK_SIZE];
    let mut total_bytes_read = 0;
    let mut blocks_to_hashes = Vec::new();

    image.seek(SeekFrom::Start(offset as u64))?;
    let mut image_take = image.take(size as u64);

    loop {
        let bytes_read = image_take.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        total_bytes_read += bytes_read;

        let block_hash = checksum(Crc64Nvme, &buffer[..bytes_read]);
        blocks_to_hashes.push(block_hash);

        if total_bytes_read % (1024 * 1024 * 100) == 0 {
            println!("status: read {} MiB", total_bytes_read / (1024 * 1024));
        }
    }

    println!(
        "Finished reading: total_bytes_read={} MiB",
        total_bytes_read / (1024 * 1024)
    );

    Ok(blocks_to_hashes)
}

pub fn hashes_to_blocks_map_from_block_hashes(block_hashes: Vec<u64>) -> HashMap<u64, usize> {
    let mut hashes_to_blocks = HashMap::new();

    for (block_num, hash) in block_hashes.iter().enumerate() {
        hashes_to_blocks.insert(*hash, block_num);
    }

    hashes_to_blocks
}

// this creates an array where the index is the block index in the new_image,
// and the value is either:
// 0: in case the block is not present in the old_image
// or otherwise, it's the block num in the old_image
pub fn get_new_to_old_block_mapping(
    old_image_hashes_to_blocks: HashMap<u64, usize>,
    new_image_blocks_to_hashes: Vec<u64>,
) -> (usize, Vec<u64>) {
    let mut new_blocks_to_old_blocks: Vec<u64> = Vec::new();
    let mut n_blocks_avail_in_old_image = 0;

    for hash in new_image_blocks_to_hashes.iter() {
        if let Some(block_num_in_old_image) = old_image_hashes_to_blocks.get(hash) {
            new_blocks_to_old_blocks.push(*block_num_in_old_image as u64);
            n_blocks_avail_in_old_image += 1;
        } else {
            new_blocks_to_old_blocks.push(u64::MAX);
        }
    }

    (n_blocks_avail_in_old_image, new_blocks_to_old_blocks)
}

pub fn measure_sha256sum(filename: &str) -> Result<[u8; 32], Box<dyn Error>> {
    // we call sha256sum/cksum externally because it's way faster than calculating it ourselves
    let cmd_out = Command::new("cksum")
        .arg("-a")
        .arg("sha256")
        .arg("--raw")
        .arg(filename)
        .output()?;

    Ok(cmd_out
        .stdout
        .get(..)
        .ok_or("arr out of bounds")?
        .try_into()?)
}
