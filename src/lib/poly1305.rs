use rug::{integer::Order, Integer};
use std::fmt::Write;

const P_STR: &str = "3fffffffffffffffffffffffffffffffb";
const R_CLAMP_MASK_STR: &str = "0ffffffc0ffffffc0ffffffc0fffffff";

/// converts an integer to a little-endian hexadecimal string
pub fn le_string_from_integer(i: &Integer) -> String {
    i.to_digits::<u8>(Order::Lsf)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// converts a little-endian hexadecimal string to a bytes array
fn bytes_from_le_str(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0);
    let bytes = s
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .map(|byte| u8::from_str_radix(&byte, 16).unwrap())
        .collect::<Vec<u8>>();
    bytes
}

/// converts a little-endian hexadecimal string to an integer
fn integer_from_le_str(s: &str) -> Integer {
    Integer::from_digits(&bytes_from_le_str(s), Order::Lsf)
}

/// extracts r and s from the key (64-character little-endian hexadecimal string)
fn extract_rs(key: &[u8]) -> (Integer, Integer) {
    (
        Integer::from_digits(&key[0..16], Order::Lsf),
        Integer::from_digits(&key[16..32], Order::Lsf),
    )
}

fn clamp_r(r: &Integer) -> Integer {
    let mask = Integer::from_str_radix(R_CLAMP_MASK_STR, 16).unwrap();
    mask & r
}

/// computes the expected poly1305 tag
fn poly1305_tag_integers(message: &[Integer], r: &Integer, s: &Integer, p: &Integer) -> Integer {
    let acc = message
        .iter()
        .fold(Integer::from(0), |acc, i| ((acc + i) * r) % p);

    (acc + s) % (Integer::from(1) << 128)
}

pub fn poly1305_tag(message: &[u8], key: &[u8]) -> Integer {
    let p = Integer::from_str_radix(P_STR, 16).unwrap();

    let message_integers: Vec<Integer> = message
        .chunks(16)
        .map(|chunk| {
            Integer::from_digits(chunk, Order::Lsf) + (Integer::from(1) << (chunk.len() << 3))
        })
        .collect();

    let (r, s) = extract_rs(key);
    let r = clamp_r(&r);

    poly1305_tag_integers(&message_integers, &r, &s, &p)
}

/// generates the poly1305 tag for a given file and key
pub fn poly1305_gen(filename: &str, key: &str) -> Integer {
    let file_bytes: Vec<u8> = std::fs::read(filename).expect("Could not read file");
    poly1305_tag(&file_bytes, &bytes_from_le_str(key))
}

/// checks if the provided poly1305 tag for a given file and key is correct
pub fn poly1305_check(filename: &str, key: &str, auth_tag: &str) -> bool {
    let tag = poly1305_gen(filename, key);
    let auth_tag_int = integer_from_le_str(auth_tag);
    tag == auth_tag_int
}
