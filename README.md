# sysupdate-delta-updater-scripts

This repo contains the scripts written as part of the delta updater for systemd-sysupgrade
project.

Since I'm new to Rust, this is also my personal playground for learning Rust.

## Tools in this repo

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

- update_image: Create/Update an existing image using deltas, passing in the old
image, a delta-update manifest, and a new image.

- update_image_downloading: Create/Update an existing image using deltas, passing
in the (local) old image, a (remote) delta-update manifest, and a (remote) new image
to take the deltas from.

- varlink_test_server_client: A minimal varlink server and client using zlink in order
to prototype passing FDs via varlink and opening them on the varlink server side. The
varlink server then uses libcryptsetup-rs to create the dm-verity data for a given disk
image that was passed in as a FD. Also useful to test the varlink server in a
locked-down environment, as that's what we'll be working with as an actual sysupdate
pull backend later. For a systemd-run command to lock down the environment, see
test_pull_server.rs.
