use clap::{arg, command, value_parser};
use poly1305::lib::{
    chacha20::{Key, Nonce},
    chacha_poly_aed::aead_chacha20_poly1305_wrap,
    poly1305::le_string_from_integer,
};

fn main() {
    // deal with command line arguments
    let matches = command!()
        .arg(
            arg!([KEY_FILE] "name of a file containing a 64-byte key (as binary data, not hex-encoded)")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([NONCE] "24-character hexadecimal string representing a 12-byte nonce")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([AD_FILE] "name of the file containing the associated data (as binary data)")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([PLAINTEXT_FILE] "name of the file containing the plaintext to be encrypted (as binary data)")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([CIPHER_FILE] "name of the file containing the cipher text to be created (as binary data)")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    let key_file = matches.get_one::<String>("KEY_FILE").unwrap();
    let key_bytes = std::fs::read(key_file).expect("Key file not found");
    let key: Key = key_bytes
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("Key file must be 64 bytes long")))
        .collect::<Vec<u32>>()
        .try_into()
        .expect("Key file must be 64 bytes long");

    let nonce_str = matches.get_one::<String>("NONCE").unwrap();
    assert!(nonce_str.len() == 24, "Nonce must be 12 bytes long");
    let nonce_bytes = nonce_str
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .map(|byte| {
            u8::from_str_radix(&byte, 16).expect("Nonce is not a valid 12 bytes hexadecimal string")
        })
        .collect::<Vec<u8>>();
    let nonce: Nonce = nonce_bytes
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u32>>()
        .try_into()
        .unwrap();

    let ad_file = matches.get_one::<String>("AD_FILE").unwrap();
    let ad = std::fs::read(ad_file).expect("AD file not found");

    let plaintext_file = matches.get_one::<String>("PLAINTEXT_FILE").unwrap();
    let plaintext = std::fs::read(plaintext_file).expect("Plaintext file not found");

    let cipher_file = matches.get_one::<String>("CIPHER_FILE").unwrap();

    let (ciphertext, tag) = aead_chacha20_poly1305_wrap(&ad, &key, &nonce, &plaintext);

    std::fs::write(cipher_file, ciphertext).expect("Could not write output in cipher file");
    print!("{}", le_string_from_integer(&tag));
}
