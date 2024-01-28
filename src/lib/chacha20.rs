fn chacha20_quarter_round_operation(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);
    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

type State = [u32; 16];
pub type Key = [u32; 8];
pub type Nonce = [u32; 3];
type Block = [u8; 64];

fn chacha20_quarter_round(state: &mut State, i: usize, j: usize, k: usize, l: usize) {
    let mut chunks = state.chunks_mut(4);

    chacha20_quarter_round_operation(
        &mut chunks.next().unwrap()[i % 4],
        &mut chunks.next().unwrap()[j % 4],
        &mut chunks.next().unwrap()[k % 4],
        &mut chunks.next().unwrap()[l % 4],
    );
}

fn bytes_from_state(state: &State) -> [u8; 64] {
    let mut result = [0u8; 64];
    for i in 0..64 {
        result[i] = (state[i >> 2] >> ((i % 4) << 3)) as u8;
    }
    result
}

fn chacha20_block(key: &Key, nonce: &Nonce, count: u32) -> Block {
    let mut state: State = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, key[0], key[1], key[2], key[3], key[4],
        key[5], key[6], key[7], count, nonce[0], nonce[1], nonce[2],
    ];
    let initial_state = state.clone();
    for _ in 0..10 {
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }
    for (a, &b) in state.iter_mut().zip(&initial_state) {
        *a = a.wrapping_add(b);
    }
    bytes_from_state(&state)
}

pub fn chacha20(key: &Key, counter: u32, nonce: &Nonce, plaintext: &[u8]) -> Vec<u8> {
    let mut ciphertext = plaintext.to_vec();
    for (i, chunk) in ciphertext.chunks_mut(64).enumerate() {
        let key_stream = chacha20_block(key, nonce, counter + (i as u32));
        for (a, b) in chunk.iter_mut().zip(&key_stream) {
            *a ^= b;
        }
    }
    ciphertext
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_chacha20_quarter_round_operation() {
        let mut a = 0x11111111;
        let mut b = 0x01020304;
        let mut c = 0x9b8d6f43;
        let mut d = 0x01234567;
        chacha20_quarter_round_operation(&mut a, &mut b, &mut c, &mut d);
        assert_eq!(a, 0xea2a92f4);
        assert_eq!(b, 0xcb1cf8ce);
        assert_eq!(c, 0x4581472e);
        assert_eq!(d, 0x5881c4bb);
    }

    #[test]
    fn test_chacha20_quarter_round() {
        let mut state: State = [
            0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0x2a5f714c, 0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0x3d631689,
            0x2098d9d6, 0x91dbd320,
        ];
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        let expected: State = [
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a, 0x44c20ef3, 0x3390af7f, 0xd9fc690b,
            0xcfacafd2, 0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963, 0x5c971061, 0xccc07c79,
            0x2098d9d6, 0x91dbd320,
        ];
        assert_eq!(state, expected);
    }

    #[test]
    fn test_chacha20_block() {
        let key: Key = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c,
        ];
        let nonce: Nonce = [0x09000000, 0x4a000000, 0x00000000];
        let count = 1;
        let expected_block: Block = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(chacha20_block(&key, &nonce, count), expected_block);
    }

    #[test]
    fn test_chacha20() {
        let plaintext_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let plaintext = plaintext_str.as_bytes();
        let key: Key = [
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918,
            0x1f1e1d1c,
        ];
        let nonce: Nonce = [0x00000000, 0x4a000000, 0x00000000];
        let counter = 1;
        let cyphertext = chacha20(&key, counter, &nonce, plaintext);
        let expected_cyphertext = [
            0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
            0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
            0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
            0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
            0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
            0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
            0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
            0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
            0x87, 0x4d,
        ];
        assert_eq!(cyphertext, expected_cyphertext);
    }
}
