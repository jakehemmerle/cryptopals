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
    use crate::set_two::aes::{Block, CipherMode, AES128};
    use std::fs;

    let ciphertext = input_to_blocks(
        base64::decode(
            fs::read_to_string("src/set_two/2-2.txt")
                .unwrap()
                .replace("\n", ""),
        )
        .unwrap()
        .as_ref(),
    );

    let key = b"YELLOW SUBMARINE";
    let iv = GenericArray::<u8, U16>::from([0u8; 16]);

    let cipher = AES128::new(CipherMode::CBC(iv), key);

    // fill plaintext with zeros
    let mut plaintext = output_from_block_count(ciphertext.len());

    // print plaintext
    cipher.decrypt(ciphertext.as_slice(), plaintext.as_mut_slice());

    // println!("plaintext after: {:?}", plain);
    plaintext.iter().for_each(|block| {
        println!(
            "{}",
            String::from_utf8(block.to_vec()).unwrap_or_else(|_| "invalid utf8".to_string())
        )
    });
}

/// this generates an output buffer from the block count (assuming 16-byte blocks)
pub fn output_from_block_count(block_count: usize) -> Vec<GenericArray<u8, U16>> {
    let mut plain = Vec::<u8>::with_capacity(block_count * 16);
    for _ in 0..(block_count * 16) {
        plain.push(0);
    }
    let plaintext = plain
        .chunks(16)
        .into_iter()
        .map(|c| GenericArray::<u8, U16>::clone_from_slice(c))
        .collect_vec();

    plaintext
}

/// This turns a slice of bytes (eg ciphertext) into 16 byte blocks ready for encryption;
pub fn input_to_blocks(input: &[u8]) -> Vec<GenericArray<u8, U16>> {
    let mut output = Vec::<u8>::with_capacity(input.len());
    output.extend_from_slice(input);
    let padding = 16 - (input.len() % 16);
    output.extend(vec![42u8; padding]);

    let blocks = output
        .chunks(16)
        .into_iter()
        .map(|c| GenericArray::<u8, U16>::clone_from_slice(c))
        .collect_vec();

    blocks
}
