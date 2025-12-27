use bytes::Bytes;
use crc_fast::{CrcAlgorithm::Crc64Nvme, checksum};
use gvariant::{Marker, Structure, aligned_bytes::copy_to_align, gv};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io;
use std::io::SeekFrom;
use std::io::{Read, Seek};
use std::process::Command;

pub const BLOCK_SIZE: usize = 4096;

pub struct Manifest {
    pub version: u32,           /* manifest version */
    pub verity_salt: [u8; 32],  /* salt to use for dm-verity */
    pub image_hash: [u8; 32],   /* sha256 hash of the image (unsalted) */
    pub block_hashes: Vec<u64>, /* block hashes crc64 */
}

fn check_manifest_version(manifest_version: &[u8]) -> Result<(), Box<dyn Error>> {
    assert!(manifest_version.len() == 4);
    let buffer = copy_to_align(manifest_version);
    let manifest_version = gv!("u").cast(&buffer);
    if *manifest_version != 1 {
        return Err(format!("Unsupported manifest version: {}", manifest_version).into());
    }

    Ok(())
}

pub fn read_manifest(manifest_filename: &str) -> Result<Manifest, Box<dyn Error>> {
    // read the first 4 bytes of the file first as a simple, forward-compatible version check
    // FIXME: I think this shouldn't cause problems with endianness etc, but not 100% sure
    let mut manifest_file = File::open(manifest_filename)?;

    let mut buffer = [0u8; 4];
    let bytes_read = manifest_file.read(&mut buffer)?;
    if bytes_read != 4 {
        return Err("Failed to read manifest version".into());
    }
    check_manifest_version(&buffer)?;

    manifest_file.rewind()?;

    let variant = gv!("(uayayat)").deserialize(manifest_file)?;
    let manifest_as_tuple = variant.to_tuple();

    let manifest = Manifest {
        version: *manifest_as_tuple.0,
        verity_salt: manifest_as_tuple.1.try_into()?,
        image_hash: manifest_as_tuple.2.try_into()?,
        block_hashes: manifest_as_tuple.3.to_vec(),
    };

    Ok(manifest)
}

pub fn read_manifest_bytes(manifest_bytes: Bytes) -> Result<Manifest, Box<dyn Error>> {
    check_manifest_version(&manifest_bytes[0..4])?;

    let buffer = copy_to_align(&manifest_bytes);
    let variant = gv!("(uayayat)").cast(&buffer);
    let manifest_as_tuple = variant.to_tuple();

    let manifest = Manifest {
        version: *manifest_as_tuple.0,
        verity_salt: manifest_as_tuple.1.try_into()?,
        image_hash: manifest_as_tuple.2.try_into()?,
        block_hashes: manifest_as_tuple.3.to_vec(),
    };

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
            new_blocks_to_old_blocks.push(0);
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
