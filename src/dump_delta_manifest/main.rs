use std::fs::{File};
use std::env;
use std::process;
use std::error::Error;
//use std::collections::HashMap;
//use sha256::digest;
//use sha2::{Sha256};
use std::io::Read;
use gvariant::{gv, Marker, Structure, aligned_bytes::copy_to_align};

struct Manifest {
  version: u32,           /* manifest version */
  verity_salt: [u8; 32],  /* salt to use for dm-verity */
  image_hash: [u8; 32],   /* sha256 hash of the image (unsalted) */
  hash_blocks: Vec<u64>,  /* block hashes crc64 */
}

fn help() {
    println!("usage: dump_delta_manifest <manifest>

Dump the data from a delta update manifest file <manifest>.");
}

fn check_manifest_version(manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    let mut manifest_file = File::open(manifest_filename)?;

    // read the first 4 bytes of the file first as a simple, forward-compatible version check
    // FIXME: I think this shouldn't cause problems with endianness etc, but not 100% sure
    let mut buffer = [0u8; 4];
    let bytes_read = manifest_file.read(&mut buffer)?;
    if bytes_read != 4 {
        return Err("Failed to read manifest version".into())
    }
    let buffer = copy_to_align(&buffer);
    let manifest_version = gv!("u").cast(&buffer);
    if *manifest_version != 1 {
        return Err(format!("Unsupported manifest version: {}", manifest_version).into())
    }

    Ok(())
}

fn dump_manifest(manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    check_manifest_version(manifest_filename)?;

    let manifest_file = File::open(manifest_filename)?;
    let variant = gv!("(uayayat)").deserialize(manifest_file)?;
    let manifest_as_tuple = variant.to_tuple();

    let manifest = Manifest {
        version: *manifest_as_tuple.0,
        verity_salt: manifest_as_tuple.1.try_into()?,
        image_hash: manifest_as_tuple.2.try_into()?,
        hash_blocks: manifest_as_tuple.3.to_vec(),
    };

    println!("version: {:?}", manifest.version);
    println!("salt: {:?}", manifest.verity_salt);
    println!("sha256hash of image: {:?}", manifest.image_hash);
    println!("number of hash blocks: {}", manifest.hash_blocks.len());

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => {
            let manifest_filename = &args[1];

            dump_manifest(manifest_filename)
        },
        _ => {
            help();
            process::exit(1)
        }
    }
}
