use clap::{arg, command, value_parser};
use poly1305::lib::chacha20::{chacha20, Key, Nonce};

fn main() {
    // deal with command line arguments
    let matches = command!()
        .arg(
            arg!([KEY_FILE] "name of a file containing a 64-byte key (as binary data, not hex-encoded)")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([NONCE] "a 24-character hexadecimal string representing a 12-byte nonce")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([MESSAGE_FILE] "name of the file containing the clear text to be encrypted (as binary data)")
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

    let message_file = matches.get_one::<String>("MESSAGE_FILE").unwrap();
    let plaintext = std::fs::read(message_file).unwrap();

    let cipher_file = matches.get_one::<String>("CIPHER_FILE").unwrap();

    std::fs::write(cipher_file, chacha20(&key, 1, &nonce, &plaintext))
        .expect("Could not write output in cipher file");
}
