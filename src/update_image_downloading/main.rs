use futures::executor::block_on;
use multipart_async_stream::{
    LendingIterator, MultipartStream, TryStreamExt, header::CONTENT_TYPE,
};
use reqwest::Client;
use std::cmp::min;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::num::ParseIntError;
use std::process;
use std::process::Command;

use sysupdate_delta_updater_scripts::delta_manifest;

const N_RANGES_PER_DOWNLOAD: usize = 800;

fn help() {
    println!(
        "usage: update_image_downloading <old_image> <image_to_update> <new_image_url>

Update <image_to_update> using delta, using <old_image> as the old image, 
and <new_image_url> as the (remote) source for the new image, as well as 
<new_image_manifest_url> as the (remote) source for the new image manifest."
    );
}

fn copy_block(
    mut source: &File,
    source_block_num: u64,
    mut target: &File,
    target_block_num: u64,
) -> Result<(), Box<dyn Error>> {
    source.seek(std::io::SeekFrom::Start(
        source_block_num * delta_manifest::BLOCK_SIZE as u64,
    ))?;
    let mut source_take = source.take(delta_manifest::BLOCK_SIZE as u64);

    target.seek(std::io::SeekFrom::Start(
        target_block_num * delta_manifest::BLOCK_SIZE as u64,
    ))?;

    std::io::copy(&mut source_take, &mut target)?;

    Ok(())
}

async fn download_blocks_multipart(
    client: &Client,
    mut target: &File,
    downloads: &[(usize, u64)],
    url: &str,
) -> Result<(), Box<dyn Error>> {
    let mut header = "bytes=".to_string();

    for (offset, n_chunks) in downloads {
        if header != "bytes=" {
            header.push_str(",");
        }
        let start_bytes: u64 = *offset as u64 * (delta_manifest::BLOCK_SIZE as u64);
        let end_bytes: u64 = start_bytes + ((delta_manifest::BLOCK_SIZE as u64) * n_chunks) - 1;

        header.push_str(&format!("{}-{}", start_bytes, end_bytes));
    }

    let response = client.get(url).header("Range", header).send().await?;
    if !response.status().is_success() {
        return Err("Delta download failed".into());
    }

    let content_type_header = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok());

    if content_type_header.is_some_and(|h| h.contains("multipart/byteranges")) {
        let boundary = content_type_header
            .unwrap()
            .split("boundary=")
            .nth(1)
            .map(|s| s.trim().as_bytes().to_vec().into_boxed_slice());
        let mut m = MultipartStream::new(response.bytes_stream(), &boundary.unwrap());

        let mut d_iter = downloads.into_iter();
        while let Some((offset, _n_chunks)) = d_iter.next() {
            let Some(Ok(part)) = m.next().await else {
                break;
            };

            target.seek(std::io::SeekFrom::Start(
                *offset as u64 * delta_manifest::BLOCK_SIZE as u64,
            ))?;

            let mut body = part.body();
            while let Ok(Some(b)) = body.try_next().await {
                target.write_all(&*b)?;
            }
        }
    } else if content_type_header.is_some_and(|h| h == "application/octet-stream")
        || content_type_header.is_none()
    {
        assert!(downloads.len() == 1);
        let (offset, _n_chunks) = downloads[0];

        target.seek(std::io::SeekFrom::Start(
            offset as u64 * delta_manifest::BLOCK_SIZE as u64,
        ))?;
        let s = response.bytes().await?;
        target.write_all(&*s)?;
    } else {
        return Err("Delta download returned wrong content type".into());
    }

    Ok(())
}

fn update_image(
    source_image: &str,
    image_to_update: &str,
    new_image_url: &str,
    blocks_to_update: Vec<u64>,
) -> Result<(), Box<dyn Error>> {
    let source_image_file = File::open(source_image)?;
    let mut image_to_update_file = File::create(image_to_update)?;
    //let mut image_to_update_file = OpenOptions::new().write(true).open(image_to_update)?;

    let mut n_chunks_cur_download = 0;
    let mut begin_block_cur_download = 0;
    let mut downloads = Vec::new();

    /*
        env_logger::Builder::from_default_env()
            .filter(None, LevelFilter::Trace)
            .init();
    */

    // FIXME: for some reason the reqwest library sometimes just doesn't send a
    // request over the network. It's consistently the 6th or so request submitted.
    // The problem seems to be specific to some web servers and only to https.
    // A workaround seems to be using the rustls tls implementation (or native?).
    //let client = reqwest::ClientBuilder::new().use_rustls_tls().build().unwrap();
    let client = reqwest::ClientBuilder::new().build().unwrap();

    for (target_block_num, source_block_num) in blocks_to_update.iter().enumerate() {
        if *source_block_num == 0 {
            if n_chunks_cur_download == 0 {
                begin_block_cur_download = target_block_num;
                n_chunks_cur_download = 1;
            } else {
                n_chunks_cur_download += 1;
            }
        } else {
            if n_chunks_cur_download > 0 {
                downloads.push((begin_block_cur_download, n_chunks_cur_download));
                n_chunks_cur_download = 0;
            }

            copy_block(
                &source_image_file,
                *source_block_num,
                &image_to_update_file,
                target_block_num as u64,
            )?;
        }
    }

    if n_chunks_cur_download > 0 {
        downloads.push((begin_block_cur_download, n_chunks_cur_download));
    }

    println!("Finished copying unchanged blocks, now downloading deltas");

    let mut i = 0;
    while i < downloads.len() {
        let end_cur_range = min(i + N_RANGES_PER_DOWNLOAD, downloads.len());
        let future = download_blocks_multipart(
            &client,
            &image_to_update_file,
            &downloads[i..end_cur_range],
            new_image_url,
        );
        block_on(future)?;

        i = i + N_RANGES_PER_DOWNLOAD;
    }

    image_to_update_file.flush()?;

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

fn create_verity_image(
    new_image: &str,
    new_verity_image: &str,
    verity_salt: [u8; 32],
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut salt_string = String::new();
    for byte in verity_salt {
        salt_string.push_str(&format!("{:02x}", byte));
    }

    let cmd_out = Command::new("veritysetup")
        .arg("format")
        .arg(new_image)
        .arg(new_verity_image)
        .arg("--salt")
        .arg(salt_string)
        .output()?;

    let out_str = String::from_utf8(cmd_out.stdout)?;

    let root_hash = out_str
        .lines()
        .nth(9)
        .expect("not a line")
        .split("\t")
        .nth(1)
        .expect("not a str");
    let root_as_vec = (*decode_hex(root_hash)?).try_into()?;

    Ok(root_as_vec)
}

fn delta_update_image(
    old_image: &str,
    image_to_update: &str,
    new_image_url: &str,
    new_image_manifest_url: &str,
) -> Result<(), Box<dyn Error>> {
    let old_image_manifest_filename = format!("{old_image}.manifest");
    let old_image_hashes_to_blocks = if let Ok(old_image_manifest) =
        delta_manifest::read_manifest(&old_image_manifest_filename)
    {
        println!(
            "Found old image manifest at \"{}\"",
            old_image_manifest_filename
        );
        delta_manifest::hashes_to_blocks_map_from_block_hashes(old_image_manifest.block_hashes)
    } else {
        println!("No old image manifest, reading image to get block hashes");
        let old_image_block_hashes = delta_manifest::read_image_block_hashes(old_image)?;
        delta_manifest::hashes_to_blocks_map_from_block_hashes(old_image_block_hashes)
    };

    let future = download_manifest(new_image_manifest_url);
    let new_image_manifest = block_on(future)?;
    let new_image_block_hashes = new_image_manifest.block_hashes;

    let (n_blocks_avail_in_old_image, new_blocks_to_old_blocks) =
        delta_manifest::get_new_to_old_block_mapping(
            old_image_hashes_to_blocks,
            new_image_block_hashes,
        );

    println!(
        "Percentage of blocks avail from existing image: {}",
        n_blocks_avail_in_old_image as f32 / new_blocks_to_old_blocks.len() as f32
    );
    println!(
        "Download size: {} MiB",
        ((new_blocks_to_old_blocks.len() - n_blocks_avail_in_old_image)
            * delta_manifest::BLOCK_SIZE)
            / 1024
            / 1024
    );

    update_image(
        old_image,
        image_to_update,
        new_image_url,
        new_blocks_to_old_blocks,
    )?;

    println!("Now checking sha256sum of updated image");
    let sha256sum = delta_manifest::measure_sha256sum(image_to_update)?;
    if sha256sum != new_image_manifest.image_hash {
        return Err("sha256sum of updated image doesn't match the one from manifest".into());
    }

    let verity_image_filename = &format!("{image_to_update}.verity");
    println!(
        "Now creating new verity image: \"{}\"",
        verity_image_filename
    );
    let root_hash = create_verity_image(
        image_to_update,
        verity_image_filename,
        new_image_manifest.verity_salt,
    )?;
    print!("dm-verity root hash: ");
    for byte in root_hash {
        print!("{:02x}", byte);
    }
    print!("\n");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        5 => {
            let old_image = &args[1];
            let image_to_update = &args[2];
            let new_image_url = &args[3];
            let new_image_manifest_url = &args[4];

            delta_update_image(
                old_image,
                image_to_update,
                new_image_url,
                new_image_manifest_url,
            )
        }
        _ => {
            help();
            process::exit(1)
        }
    }
}
