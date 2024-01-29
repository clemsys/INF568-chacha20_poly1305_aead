all: build copy

build:
	cargo build --release

copy:
	cp target/release/poly1305_gen poly1305-gen
	cp target/release/poly1305_check poly1305-check
	cp target/release/chacha20 chacha20
	cp target/release/aead_wrap aead_wrap
	cp target/release/aead_unwrap aead_unwrap

clean:
	cargo clean
	rm chacha20 poly1305-gen poly1305-check aead_wrap aead_unwrap

