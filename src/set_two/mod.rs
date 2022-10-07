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
                .replace('\n', ""),
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
#[allow(dead_code)]
mod detection_oracle {
    use crate::set_two::aes::*;
    use crate::utils::*;

    // pub struct RandomEncryptor {}
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

// 2.4
#[allow(dead_code)]
mod byte_at_a_time {
    use crate::set_two::aes::{CipherMode, AES128};
    use crate::utils::*;
    use ::aes::Block;

    use super::pkcs_padding;
    pub struct EncryptUnknownString {
        pub(self) key: [u8; 16],
        pub(self) unknown_string: Vec<u8>,
        pub(self) cipher: AES128,
    }

    impl EncryptUnknownString {
        pub fn new() -> Self {
            // let key = rand::random::<[u8; 16]>();
            let key = [1u8; 16];

            let unknown_string = base64::decode(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK",
            )
            .unwrap();
            let cipher = AES128::new(CipherMode::ECB, &key);

            Self {
                key,
                unknown_string,
                cipher,
            }
        }

        pub fn generate_ciphertext(&self, plaintext: &[u8]) -> Vec<Block> {
            let mut modified_input =
                Vec::<u8>::with_capacity(plaintext.len() + self.unknown_string.len());
            modified_input.extend_from_slice(plaintext);
            modified_input.extend_from_slice(&self.unknown_string);
            let mod_slice = pkcs_padding(modified_input.as_slice(), 16);

            let (input, mut output) = text_to_io(mod_slice);
            self.cipher.encrypt(input.as_slice(), output.as_mut_slice());
            output
        }
    }

    #[test]
    fn byte_at_a_time_ecb() {
        use ::aes::Block;
        use itertools::Itertools;

        let encryptor = EncryptUnknownString::new();

        // find the block size and offset
        let mut block_size = 0usize;
        let mut offset = 0u8;
        let prev_ciphertext_size = encryptor
            .generate_ciphertext("A".as_bytes())
            .into_iter()
            .fold(Vec::<u8>::new(), |mut acc, block| {
                acc.extend_from_slice(block.as_slice());
                acc
            })
            .len();
        for i in 0..128u8 {
            let ciphertext = encryptor
                .generate_ciphertext("A".repeat(i as usize).as_bytes())
                .into_iter()
                .fold(Vec::<u8>::new(), |mut acc, block| {
                    acc.extend_from_slice(block.as_slice());
                    acc
                })
                .len();

            if ciphertext > prev_ciphertext_size {
                block_size = ciphertext - prev_ciphertext_size;
                offset = i;
                break;
            }
        }

        // print block size and offset
        println!("block size: {}", block_size);
        println!("offset: {}", offset);

        // detect ecb mode
        for combination in encryptor
            .generate_ciphertext("A".repeat(64).as_bytes())
            .iter()
            .enumerate()
            .combinations(2)
        {
            if combination[0].1 == combination[1].1 {
                println!("ECB mode detected! Blocks match:");
                println!("{}, {:?}", combination[0].0, combination[0].1);
                println!("{}, {:?}", combination[1].0, combination[1].1);
                break;
            }
        }

        // find the unknown string
        // generate the my_string prefix to the number of blocks the unknown string is
        let secret_block_count = encryptor.generate_ciphertext(&[]).len();
        let mut space_buff = Vec::<u8>::from(
            " ".repeat(encryptor.generate_ciphertext(&[]).len() * block_size as usize),
        );
        let mut buff = space_buff.clone();
        let mut decrypted_characters = Vec::<u8>::with_capacity(secret_block_count * block_size);
        let mut encrypted_ciphertexts = Vec::<Block>::with_capacity(space_buff.len());

        // // generate a vec of the ciphertexts you'll want to decrypt
        for _i in 0usize..space_buff.len() {
            let _string = buff.pop();
            let mut ciphertext = encryptor.generate_ciphertext(buff.as_slice());
            let get = ciphertext.remove(secret_block_count - 1);
            encrypted_ciphertexts.push(get);
            // println!("ciphertext: {:?}", get);
            // encrypted_ciphertexts.push(get);
        }

        // iterate through all of our ciphertexts now to see what we can get!
        for ciphertext_block in encrypted_ciphertexts.iter() {
            let _ = space_buff.pop();

            // this will be our string!
            let mut padding_and_discovered_chars: Vec<u8> = space_buff.clone();
            padding_and_discovered_chars.extend(decrypted_characters.clone().iter());
            // println!(
            //     "length of padding string input: {}",
            //     padding_and_discovered_chars.len()
            // );

            for character in 32..127u8 {
                //     // add character and get ciphertext
                padding_and_discovered_chars.push(character);
                let ciphertext =
                    encryptor.generate_ciphertext(padding_and_discovered_chars.as_slice());

                // print the ciphertext
                // println!(
                //     "{}",
                //     String::from_utf8(padding_and_discovered_chars.clone())
                //         .unwrap_or_else(|_| String::from("shit"))
                // );

                // get the block we want to try
                let try_block = ciphertext.get(secret_block_count - 1).unwrap();

                // // if the blocks are equal, thats our character! save it!
                if try_block == ciphertext_block {
                    decrypted_characters.push(character);
                    break;
                }

                // // remove the byte from our special string
                let _ = padding_and_discovered_chars.pop();
            }
        }

        println!(
            "learned ciphertext: {}",
            String::from_utf8(decrypted_characters).unwrap(),
        );
    }
}
