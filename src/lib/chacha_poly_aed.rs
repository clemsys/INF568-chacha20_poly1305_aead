use super::{
    chacha20::{chacha20, chacha20_block, Key, Nonce},
    poly1305::poly1305_tag,
};
use rug::Integer;

fn poly1305_key_gen(key: &Key, nonce: &Nonce) -> [u8; 32] {
    chacha20_block(key, nonce, 0)[0..32].try_into().unwrap()
}

const fn padded_size_16(size: usize) -> usize {
    (size + (1 << 4) - 1) & (usize::MAX - 0xf)
}

const fn padded_size_8(size: usize) -> usize {
    (size + (1 << 2) - 1) & (usize::MAX - 0b0111)
}

fn aead_chacha20_poly1305(
    aad: &[u8],
    key: &Key,
    nonce: &Nonce,
    plaintext: &[u8],
) -> (Vec<u8>, Integer) {
    let poly_key = poly1305_key_gen(key, nonce);
    let ciphertext = chacha20(key, 1, nonce, plaintext);

    let mut mac_data: Vec<u8> = Vec::new();

    let mut padded_aad = aad.to_vec();
    padded_aad.resize(padded_size_16(aad.len()), 0);
    mac_data.append(&mut padded_aad);

    let mut padded_ciphertext = ciphertext.clone();
    padded_ciphertext.resize(padded_size_16(padded_ciphertext.len()), 0);
    mac_data.append(&mut padded_ciphertext);

    let mut padded_aad_len = usize::to_le_bytes(aad.len()).to_vec();
    padded_aad_len.resize(8, 0);
    mac_data.append(&mut padded_aad_len);

    let mut padded_ciphertext_len = usize::to_le_bytes(ciphertext.len()).to_vec(); // do it now, before ciphertext is consumed
    padded_ciphertext_len.resize(8, 0);
    mac_data.append(&mut padded_ciphertext_len);

    (ciphertext, poly1305_tag(&mac_data, &poly_key))
}

#[cfg(test)]
mod test {
    use super::super::poly1305::le_string_from_integer;
    use super::*;

    #[test]
    fn test_poly1305_keygen() {
        let key: Key = [
            0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c, 0x93929190, 0x97969594, 0x9b9a9998,
            0x9f9e9d9c,
        ];
        let nonce: Nonce = [0x00000000, 0x03020100, 0x07060504];
        let poly_key = poly1305_key_gen(&key, &nonce);
        let expected_poly_key = [
            0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
            0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
            0xfd, 0xd1, 0xa6, 0x46,
        ];
        assert_eq!(poly_key, expected_poly_key);
    }

    #[test]
    fn test_aead_chacha20_poly1305() {
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key: Key = [
            0x83828180, 0x87868584, 0x8b8a8988, 0x8f8e8d8c, 0x93929190, 0x97969594, 0x9b9a9998,
            0x9f9e9d9c,
        ];
        let nonce: Nonce = [0x00000007, 0x43424140, 0x47464544];
        let plaintext = std::fs::read("tests/samples/chacha20/sunscreen.txt").unwrap();
        let expected_ciphertext = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];

        let (ciphertext, tag) = aead_chacha20_poly1305(&aad, &key, &nonce, &plaintext);
        assert_eq!(
            le_string_from_integer(&tag),
            "1ae10b594f09e26a7e902ecbd0600691"
        );
        assert_eq!(ciphertext, expected_ciphertext);
    }
}
