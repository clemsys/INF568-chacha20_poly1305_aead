# INF568 Assignment 3 - chacha20/poly1305

Author: [Clément CHAPOT](mailto:clement.chapot@polytechnique.edu) <br>
Description: implementation of chacha20/poly1305 (see: [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)) as part of INF568 course at École polytechnique

## Building

Build the project using `make`.

This calls `cargo build --release` and copies binaries from `target/release/` into the project root.

## Running

Run using `./poly1305-gen`, `./poly1305-check`, `./chacha20`, `./aead_wrap` or `./aead_unwrap`.

For more usage information, use `--help` on the relevant binary.

## Testing

Run `cargo test` to check if the binaries produce the right output, checking `poly1305-{gen,check}` against `openssl` and the other binaries against the tests provided in the RFC.

## Project structure

The core of the project can be found in `src/lib/`. The files in `src/bin/` are here to produce binaries, so they only contain a main function, which call functions from `src/lib/` directly.
