use gvariant::{Marker, gv};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::process;

use sysupdate_delta_updater_scripts::delta_manifest;

fn help() {
    println!(
        "usage: create_delta_manifest <image>

Create a delta update manifest for the image file <image>."
    );
}

fn generate_salt() -> Result<[u8; 32], io::Error> {
    // read 32 bytes from /dev/random to get a salt
    let mut rng = File::open("/dev/random")?;

    let mut salt = [0u8; 32];
    rng.read_exact(&mut salt)?;

    Ok(salt)
}

fn create_manifest(image: &str, manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    let salt = generate_salt()?;
    println!("salt: {:?}", salt);

    let sha256sum = delta_manifest::measure_sha256sum(image)?;
    println!("sha256sum of image: {:?}", sha256sum);

    let block_hashes = delta_manifest::read_image_block_hashes(image)?;
    println!("number of block hashes: {}", block_hashes.len());

    let manifest = delta_manifest::Manifest {
        version: 1,
        verity_salt: salt,
        image_hash: sha256sum,
        block_hashes: block_hashes,
    };

    let mut manifest_file = File::create(manifest_filename)?;
    let manifest_as_tuple = (
        manifest.version,
        manifest.verity_salt,
        manifest.image_hash,
        &manifest.block_hashes,
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
        }
        _ => {
            help();
            process::exit(1)
        }
    }
}
