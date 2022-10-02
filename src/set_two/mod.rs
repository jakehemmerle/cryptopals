mod aes;

/// 2.1
#[allow(dead_code)]
pub fn pkcs_padding(input: &[u8], block_size: usize) -> Vec<u8> {
    let mut output = input.to_vec();
    let padding = block_size - (input.len() % block_size);
    output.extend(vec![padding as u8; padding]);
    output
}

/// 2.1
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
    use crate::utils::*;
    use ::aes::cipher::{generic_array::GenericArray, typenum::U16};
    use std::fs;

    let ciphertext = input_to_padded_blocks(
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

// 2.3
mod detection_oracle {
    use crate::set_two::aes::*;
    use crate::utils::*;

    // pub struct RandomEncryptor {}
    #[allow(dead_code)]
    pub fn random_encryptor(plaintext: &[u8]) -> Vec<Block> {
        // generate randon key and blockmode
        let random_key = Block::from(rand::random::<[u8; 16]>());
        let encryption_mode_is_ecb = rand::random::<bool>();
        println!(
            "SECRET!: encryption mode is {}",
            if encryption_mode_is_ecb { "ECB" } else { "CBC" }
        );
        println!();

        // generate random length suffix
        let suffix_len = (rand::random::<u8>() % 5) + 5;
        let mut suffix = Vec::<u8>::with_capacity(suffix_len as usize);
        for _ in 0..suffix_len {
            suffix.push(rand::random::<u8>());
        }

        // generate random length prefix
        let prefix_len = (rand::random::<u8>() % 5) + 5;
        let mut prefix = Vec::<u8>::with_capacity(prefix_len as usize);
        for _ in 0..prefix_len {
            prefix.push(rand::random::<u8>());
        }

        // add prefix and suffix to plaintext
        let mut plaintext_with_rand_bytes =
            Vec::<u8>::with_capacity(plaintext.len() + prefix_len as usize + suffix_len as usize);
        plaintext_with_rand_bytes.extend(prefix);
        plaintext_with_rand_bytes.extend(plaintext);
        plaintext_with_rand_bytes.extend(suffix);

        // generate input and outputs for cipher
        let (input, mut output) = text_to_io(plaintext_with_rand_bytes);

        let cipher: AES128;
        if encryption_mode_is_ecb {
            // encrypt with ecb
            cipher = AES128::new(CipherMode::ECB, &random_key);
            cipher.encrypt(input.as_slice(), output.as_mut_slice())
        } else {
            // encrypt with cbc
            let random_iv = Block::from(rand::random::<[u8; 16]>());
            cipher = AES128::new(CipherMode::CBC(random_iv), &random_key);
            cipher.encrypt(input.as_slice(), output.as_mut_slice())
        }

        // return ciphertext
        output
    }

    /// 2.3
    #[test]
    fn test_random_encryptor() {
        let random_input = [0u8; 64];
        let ciphertext = random_encryptor(&random_input);
        println!("ciphertext:");
        for block in ciphertext.iter() {
            println!("{:?}", block);
        }

        println!();
        if ciphertext[2] == ciphertext[3] {
            println!("Detected mode: ECB");
        } else {
            println!("Detected mode: CBC");
        }
    }
}
