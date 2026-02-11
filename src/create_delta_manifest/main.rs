use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::process;
use sysupdate_delta_updater_scripts::delta_manifest;
use zvariant::{LE, serialized::Context, to_writer};

fn help() {
    println!(
        "usage: create_delta_manifest <image>

Create a delta update manifest for the image file <image>."
    );
}

fn create_manifest(image: &str, manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    let serialize_context = Context::new_gvariant(LE, 0);

    let manifest = delta_manifest::Manifest {
        block_hashes: delta_manifest::read_image_block_hashes(image)?,
    };
    println!("number of block hashes: {}", manifest.block_hashes.len());

    let mut manifest_file = File::create(manifest_filename)?;

    // SAFETY: No FDs are being serialized here so its completely safe.
    unsafe { to_writer(&mut manifest_file, serialize_context, &manifest) }?;

    manifest_file.flush()?;

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
