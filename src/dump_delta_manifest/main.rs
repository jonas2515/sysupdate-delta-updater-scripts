use std::env;
use std::error::Error;
use std::process;

use sysupdate_delta_updater_scripts::delta_manifest;

fn help() {
    println!(
        "usage: dump_delta_manifest <manifest>

Dump the data from a delta update manifest file <manifest>."
    );
}

fn dump_manifest(manifest_filename: &str) -> Result<(), Box<dyn Error>> {
    let manifest = delta_manifest::read_manifest(manifest_filename)?;

    println!("number of hash blocks: {}", manifest.block_hashes.len());

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        2 => {
            let manifest_filename = &args[1];

            dump_manifest(manifest_filename)
        }
        _ => {
            help();
            process::exit(1)
        }
    }
}
