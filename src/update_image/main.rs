use std::fs::{File};
use std::io::Read;
use std::env;
use std::process;
use std::error::Error;
use std::io::Seek;
use std::io::Write;
use std::fs::OpenOptions;

use sysupdate_delta_updater_scripts::delta_manifest;

fn help() {
    println!("usage: update_image <old_image> <image_to_update> <new_image>

Update <image_to_update> using delta, using <old_image> as the old image, 
and <new_image> as the source for the new image.

This script will look for existing delta manifests by appending \".manifest to the 
image filenames, and if it finds manifests, use those to avoid reading and hashing 
the whole images.");
}

fn copy_block(mut source: &File, source_block_num: u64, mut target: &File, target_block_num: u64) -> Result<(), Box<dyn Error>> {
    source.seek(std::io::SeekFrom::Start(source_block_num * delta_manifest::BLOCK_SIZE as u64))?;
    let mut source_take = source.take(delta_manifest::BLOCK_SIZE as u64);

    target.seek(std::io::SeekFrom::Start(target_block_num * delta_manifest::BLOCK_SIZE as u64))?;

    let _bytes_copied = std::io::copy(&mut source_take, &mut target)?;

    Ok(())
}

fn update_image(source_image: &str, image_to_update: &str, new_image: &str, blocks_to_update: Vec<u64>) -> Result<(), Box<dyn Error>> {
    let source_image_file = File::open(source_image)?;
    let mut image_to_update_file = OpenOptions::new().write(true).open(image_to_update)?;
    let new_image_file = File::open(new_image)?;

    for (target_block_num, source_block_num) in blocks_to_update.iter().enumerate() {
        if *source_block_num == 0 {
            copy_block(&new_image_file, target_block_num as u64, &image_to_update_file, target_block_num as u64)?;
        } else {
            copy_block(&source_image_file, *source_block_num, &image_to_update_file, target_block_num as u64)?;
        }
    }

    image_to_update_file.flush()?;

    Ok(())
}

fn delta_update_image(old_image: &str, image_to_update: &str, new_image: &str) -> Result<(), Box<dyn Error>> {
    let old_image_hashes_to_blocks = if let Ok(old_image_manifest) = delta_manifest::read_manifest(&format!("{old_image}.manifest")) {
        println!("Found old image manifest, using it");
        delta_manifest::hashes_to_blocks_map_from_block_hashes(old_image_manifest.block_hashes)
    } else {
        println!("No old image manifest, reading image to get block hashes");
        let old_image_block_hashes = delta_manifest::read_image_block_hashes(old_image)?;
        delta_manifest::hashes_to_blocks_map_from_block_hashes(old_image_block_hashes)
    };

    let new_image_block_hashes = if let Ok(new_image_manifest) = delta_manifest::read_manifest(&format!("{new_image}.manifest")) {
        println!("Found new image manifest, using it");
        new_image_manifest.block_hashes
    } else {
        println!("No new image manifest, reading image to get block hashes");
        delta_manifest::read_image_block_hashes(new_image)?
    };

    let (n_blocks_avail_in_old_image, new_blocks_to_old_blocks) =
        delta_manifest::get_new_to_old_block_mapping(old_image_hashes_to_blocks, new_image_block_hashes);

    println!("Percentage of blocks avail from existing image: {}", n_blocks_avail_in_old_image as f32 / new_blocks_to_old_blocks.len() as f32);
    println!("Amount to copy from new image: {} MiB", ((new_blocks_to_old_blocks.len() - n_blocks_avail_in_old_image) * delta_manifest::BLOCK_SIZE) / 1024 / 1024);

    update_image(old_image, image_to_update, new_image, new_blocks_to_old_blocks)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        4 => {
            let old_image = &args[1];
            let image_to_update = &args[2];
            let new_image = &args[3];

            delta_update_image(old_image, image_to_update, new_image)
        },
        _ => {
            help();
            process::exit(1)
        }
    }
}
