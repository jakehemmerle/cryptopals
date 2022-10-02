use ::aes::cipher::{generic_array::GenericArray, typenum::U16, Block};
use itertools::Itertools;

mod aes;

/// 2.1
pub fn pkcs_padding(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let padding = block_size - (input.len() % block_size);
    output.extend(vec![padding as u8; padding]);
    output
}

#[test]
fn test_pkcs_padding() {
    let input = b"YELLOW SUBMARINE";
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    assert_eq!(pkcs_padding(input, 20), expected);
}

/// 2.2
#[test]
fn aes_cbc_decrypt() {
    use crate::set_two::aes::{CipherMode, AES128};
    use ::aes::{Aes128, Block};
    use std::fs;

    let ciphertext = base64::decode(
        fs::read_to_string("src/set_two/2-2.txt")
            .unwrap()
            .replace("\n", ""),
    )
    .unwrap()
    .chunks(16)
    .into_iter()
    .map(|c| Block::clone_from_slice(c))
    .collect_vec();

    let key = b"YELLOW SUBMARINE";
    let iv = GenericArray::<u8, U16>::from([0u8; 16]);

    let cipher = AES128::new(CipherMode::CBC(iv), key);

    // fill plaintext with zeros
    let mut plaintext = Vec::<u8>::with_capacity(ciphertext.len() * 16);
    for _ in 0..(ciphertext.len() * 16) {
        plaintext.push(0);
    }

    let mut plain = plaintext
        .chunks(16)
        .into_iter()
        .map(|c| Block::clone_from_slice(c))
        .collect_vec();

    // print plaintext
    cipher.decrypt(ciphertext.as_slice(), plain.as_mut_slice());

    // println!("plaintext after: {:?}", plain);
    plain.iter().for_each(|block| {
        println!(
            "{}",
            String::from_utf8(block.to_vec()).unwrap_or_else(|_| "invalid utf8".to_string())
        )
    });
}
