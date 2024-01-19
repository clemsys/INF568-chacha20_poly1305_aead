all: build copy

build:
	cargo build --release

copy:
	cp target/release/poly1305-gen poly1305-gen
	cp target/release/poly1305-check poly1305-check

clean:
	cargo clean
	rm poly1305-gen
	rm poly1305-check
