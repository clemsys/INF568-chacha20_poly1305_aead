use clap::{arg, command, value_parser};
use rug::{integer::Order, Integer};
use std::{fmt::Write, fs::File, io::Read};

const P_STR: &str = "3fffffffffffffffffffffffffffffffb";
const R_CLAMP_MASK_STR: &str = "0ffffffc0ffffffc0ffffffc0fffffff";

/// converts an integer to a little-endian hexadecimal string
fn le_string_from_integer(i: &Integer) -> String {
    i.to_digits::<u8>(Order::Lsf)
        .iter()
        .fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// converts a little-endian hexadecimal string to an integer
fn integer_from_le_str(s: &str) -> Integer {
    assert!(s.len() % 2 == 0);
    let bytes = s
        .chars()
        .collect::<Vec<char>>()
        .chunks(2)
        .map(|chunk| chunk.iter().collect::<String>())
        .map(|byte| u8::from_str_radix(&byte, 16).unwrap())
        .collect::<Vec<u8>>();
    Integer::from_digits(&bytes, Order::Lsf)
}

/// extracts r and s from the key (64-character little-endian hexadecimal string)
fn extract_rs(key: &str) -> (Integer, Integer) {
    (
        integer_from_le_str(&key[0..32]),
        integer_from_le_str(&key[32..64]),
    )
}

fn clamp_r(r: &Integer) -> Integer {
    let mask = Integer::from_str_radix(R_CLAMP_MASK_STR, 16).unwrap();
    mask & r
}

fn main() {
    // deal with command line arguments
    let matches = command!()
        .arg(
            arg!([KEY] "32-byte key, given as a 64-character hexadecimal string")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([FILE] "name of the file to authenticate")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // extract r and s from key
    let key = matches.get_one::<String>("KEY").unwrap();
    let (r, s) = extract_rs(key);
    let r = clamp_r(&r); // keep r immutable

    let filename = matches.get_one::<String>("FILE").unwrap();
    let mut file = File::open(filename).unwrap();
    let mut file_bytes: Vec<u8> = Vec::new();
    file.read_to_end(&mut file_bytes).unwrap();

    let message: Vec<Integer> = file_bytes
        .chunks(16)
        .map(|chunk| {
            Integer::from_digits(chunk, Order::Lsf) + (Integer::from(1) << (chunk.len() << 3))
        })
        .collect();

    let p = Integer::from_str_radix(P_STR, 16).unwrap();

    let acc = message
        .iter()
        .fold(Integer::from(0), |acc, i| ((acc + i) * &r) % &p);

    let tag = (acc + &s) % (Integer::from(1) << 128);

    print!("{}", le_string_from_integer(&tag));
}
