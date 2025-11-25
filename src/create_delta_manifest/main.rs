use std::fs::{File};
use std::io::{self, Read};
use std::env;
use std::process;
use std::error::Error;
//use std::collections::HashMap;
use crc_fast::{checksum, CrcAlgorithm::Crc64Nvme};
use std::process::Command;
use gvariant::{gv, Marker};

const BLOCK_SIZE: usize = 4096;

struct Manifest {
  version: u32,           /* manifest version */
  verity_salt: [u8; 32],  /* salt to use for dm-verity */
  image_hash: [u8; 32],   /* sha256 hash of the image (unsalted) */
  hash_blocks: Vec<u64>,  /* block hashes crc64 */
}

fn help() {
    println!("usage: create_delta_manifest <image>

Create a delta update manifest for the image file <image>.");
}

fn read_image(filename: &str) -> Result<(usize, Vec<u64>), Box<dyn Error>> {
    let mut image = File::open(filename)?;
    let mut buffer = [0u8; BLOCK_SIZE];
    let mut total_bytes_read = 0;
    let mut hashes = Vec::new();

    loop {
        let bytes_read = image.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        total_bytes_read += bytes_read;
        let _block_num = total_bytes_read / BLOCK_SIZE;

        let block_hash = checksum(Crc64Nvme, &buffer.get(..bytes_read).ok_or("arr out of bounds")?);
        hashes.push(block_hash);

        if total_bytes_read % (1024 * 1024 * 100) == 0 {
            println!("status: read {} MiB of file={}",
                     total_bytes_read / (1024 * 1024), filename);
        }
    }

    println!("Finished reading: file={}, total_bytes_read={} MiB",
             filename, total_bytes_read / (1024 * 1024));

    Ok((total_bytes_read, hashes))
}

fn generate_salt() -> Result<[u8; 32], io::Error> {
    // read 32 bytes from /dev/random to get a salt
    let mut rng = File::open("/dev/random")?;

    let mut salt = [0u8; 32];
    rng.read_exact(&mut salt)?;

    Ok(salt)
}

fn measure_sha256sum(filename: &str) -> Result<[u8; 32], Box<dyn Error>> {
    // we call sha256sum/cksum externally because it's way faster than calculating it ourselves
    let cmd_out = Command::new("cksum")
        .arg("-a")
        .arg("sha256")
        .arg("--raw")
        .arg(filename)
        .output()?;

    Ok(cmd_out.stdout.get(..).ok_or("arr out of bounds")?.try_into()?)
}

fn create_manifest(image: &str, manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    let salt = generate_salt()?;
    println!("salt: {:?}", salt);

    let sha256sum = measure_sha256sum(image)?;
    println!("sha256sum of image: {:?}", sha256sum);

    let (_, block_hashes) = read_image(image)?;
    println!("number of block hashes: {}", block_hashes.len());

    let manifest = Manifest {
        version: 1,
        verity_salt: salt,
        image_hash: sha256sum,
        hash_blocks: block_hashes,
    };

    let mut manifest_file = File::create(manifest_filename)?;
    let manifest_as_tuple = (
        manifest.version,
        manifest.verity_salt,
        manifest.image_hash,
        &manifest.hash_blocks,
    );

    gv!("(uayayat)").serialize(&manifest_as_tuple, &mut manifest_file)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => {
            let image = &args[1];
            let manifest_filename = image.to_string() + ".manifest";

            create_manifest(image, manifest_filename.as_str())
        },
        _ => {
            help();
            process::exit(1)
        }
    }
}
