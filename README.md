# sysupdate-delta-updater-scripts

This repo contains the scripts written as part of the delta updater for systemd-sysupgrade
project.

Since I'm new to Rust, this is also my personal playground for learning Rust.

## Tools that are currently in this repo:

- get_delta_info: A tool to look at two erofs images and determine the similarities
between the blocks of those images: 4 KiB blocks of both images are hashed and compared,
the tool then tells you how many matching blocks were found and whether they are
at the same positions. This can be used get informationon how large a delta update
between two OS versions can be when using our block-based delta approach.

- create_delta_manifest: Create a delta-update manifest using the binary file format
that was discussed. Used to iterate on the manifest format and potentially for tests
in  the future.

- dump_delta_manifest: Read and print the information encoded in a delta-update manifest
created using create_delta_manifest. Used to iterate on the manifest format and
potentially for tests in the future.
