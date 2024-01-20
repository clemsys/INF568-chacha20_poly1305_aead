all: build copy

build:
	cargo build --release

copy:
	cp target/release/poly1305_gen poly1305-gen
	cp target/release/poly1305_check poly1305-check

clean:
	cargo clean
	rm poly1305-gen
	rm poly1305-check
