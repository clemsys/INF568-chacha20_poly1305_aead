# INF568 Assignment 3 - chacha20/poly1305

Author: [Clément CHAPOT](mailto:clement.chapot@polytechnique.edu) <br>
Description: implementation of chacha20/poly1305 (see: [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) as part of INF568 course at École polytechnique

## Building

Build the project using `make`.

This calls `cargo build --release` and copies binaries from `target/release/` into the project root.

## Running

Run using `./poly1305-gen`, `./poly1305-check` or `./chacha20`.

For more usage information, run `./poly1305-{gen,check} --help` or `./chacha20 --help`.

## Testing

Run `cargo test` to check if `./poly1305-{gen,check}` produce the right output, comparing it with `openssl`.

## Project structure

The core of the project can be found in `src/lib.rs`. The files `src/bin/poly1305_{check,gen}.rs` and `src/bin/chacha20.rs` are here to produce binaries, so they only contain a main functions, which call `lib.rs` directly.
