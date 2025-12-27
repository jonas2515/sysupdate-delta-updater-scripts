use crc_fast::{CrcAlgorithm::Crc64Nvme, checksum};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::process;

const BLOCK_SIZE: usize = 4096;

fn help() {
    println!("usage: get_delta_info <from_image> <to_image>

Get information on the delta, using <from_image> as the existing image, and <to_image> as the target image.");
}

fn read_image(filename: &str) -> Result<(usize, HashMap<u64, usize>), io::Error> {
    let mut image = File::open(filename)?;
    let mut buffer = [0; BLOCK_SIZE];
    let mut total_bytes_read = 0;
    let mut hashes_to_block_num = HashMap::new();

    loop {
        let bytes_read: usize = image.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        total_bytes_read += bytes_read;
        let block_num = total_bytes_read / BLOCK_SIZE;

        let block_hash = checksum(Crc64Nvme, &buffer[..bytes_read]);
        if hashes_to_block_num.contains_key(&block_hash) {
            panic!(
                "collision in same file found while hashing, block_num {}",
                block_num
            );
        }

        hashes_to_block_num.insert(block_hash, block_num);

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

    Ok((total_bytes_read, hashes_to_block_num))
}

fn print_delta_information(image_from: &str, image_to: &str) -> Result<(), Box<dyn Error>> {
    let (total_bytes_read_image_from, block_hashes_image_from) = read_image(image_from)?;
    let (total_bytes_read_image_to, block_hashes_image_to) = read_image(image_to)?;
    let n_blocks_image_from = block_hashes_image_from.len();
    let n_blocks_image_to = block_hashes_image_to.len();

    let mut n_blocks_not_matching: usize = 0;
    let mut n_blocks_matching: usize = 0;
    let mut n_blocks_at_same_position: usize = 0;

    for (block_hash, block_num) in block_hashes_image_to.iter() {
        let block_num_in_image_from = block_hashes_image_from.get(block_hash);
        if block_num_in_image_from.is_none() {
            n_blocks_not_matching += 1;
            continue;
        }
        let block_num_in_image_from = block_num_in_image_from.unwrap();

        n_blocks_matching += 1;

        if block_num == block_num_in_image_from {
            n_blocks_at_same_position += 1;
        }
    }

    assert!(n_blocks_image_to == (n_blocks_matching + n_blocks_not_matching));

    let percent_matching = n_blocks_matching as f32 / n_blocks_image_to as f32;
    let percent_in_same_position = n_blocks_at_same_position as f32 / n_blocks_image_to as f32;

    println!("Finished comparing files");
    println!(
        "n_blocks_matching={}, n_blocks_not_matching={}, percent_matching={}",
        n_blocks_matching, n_blocks_not_matching, percent_matching
    );
    println!(
        "n_blocks_at_same_position={}, percent_in_same_position={}",
        n_blocks_at_same_position, percent_in_same_position
    );
    println!(
        "total_bytes_read_image_from={} ({} MiB), total_bytes_read_image_to={} ({} MiB)",
        total_bytes_read_image_from,
        total_bytes_read_image_from / (1024 * 1024),
        total_bytes_read_image_to,
        total_bytes_read_image_to / (1024 * 1024)
    );
    println!(
        "n_blocks_image_from={} ({} MiB), n_blocks_image_to={} ({} MiB)",
        n_blocks_image_from,
        (n_blocks_image_from * BLOCK_SIZE) / (1024 * 1024),
        n_blocks_image_to,
        (n_blocks_image_to * BLOCK_SIZE) / (1024 * 1024)
    );

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        3 => {
            let image_from = &args[1];
            let image_to = &args[2];

            print_delta_information(image_from, image_to)
        }
        _ => {
            help();
            process::exit(1)
        }
    }
}
