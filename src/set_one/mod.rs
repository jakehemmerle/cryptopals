// 1.6
mod repeating_key_xor_tests {
    /// This brute forces some dummy data
    #[test]
    fn brute_force_dummy_data() {
        use crate::repeating_key_xor::*;

        let ciphertext = hex::decode("1729316330212a223f6323262c363a63273b3b613e362c242625742c37313161202b24742f202d63253b246f740a6123222f2063353b6323316320362f2474372e742f282226613d2d613563253b332474332d352024742a2f740d181763363d372974092e3c2d6f740a66396331262635203a613236223f2a2f336332202c2a31276f7417293d30613d3061332c283a2461202c613626613563262626202063353d2e247a".to_string()).unwrap();
        let key_lengths = guess_key_length(&ciphertext, 5);

        for key_length in key_lengths {
            let (plaintext, key) = brute_force_ciphertext(&ciphertext.as_slice(), key_length);

            println!(
                "KEY:\n\"{}\"\n{:?}\n",
                String::from_utf8(key.clone()).unwrap_or("can't be parsed as string".to_string()),
                key
            );

            println!(
                "PLAINTEXT:\n{}",
                String::from_utf8(plaintext).unwrap_or("can't be parsed as string".to_string())
            );
        }
    }

    /// This brute forces the challenge 1.6 ciphertext
    #[test]
    fn brute_force_real_data() {
        use crate::repeating_key_xor::*;
        use std::fs;

        let file = fs::read_to_string("src/set_one/1-6.txt")
            .expect("Should have been able to read the file");
        let ciphertext = base64::decode(file.replace("\n", "")).unwrap();
        let key_lengths = guess_key_length(&ciphertext, 40);

        let (plaintext, key) = brute_force_ciphertext(&ciphertext.as_slice(), key_lengths[0]);

        println!(
            "KEY:\n\"{}\"\n{:?}\n",
            String::from_utf8(key.clone()).unwrap_or("can't be parsed as string".to_string()),
            key
        );

        println!(
            "PLAINTEXT:\n{}",
            String::from_utf8(plaintext).unwrap_or("can't be parsed as string".to_string())
        );
    }
}

// This includes challenges in set 1.1 through 1.5 and will remain undocumented
mod one_through_five {
    #[test]
    fn hex_encode_decode() {
        // convert hex to base64
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(base64::encode(hex::decode(hex).unwrap()), base64);
    }

    #[test]
    fn xor() {
        let value1 = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let value2 = hex::decode("686974207468652062756c6c277320657965").unwrap();
        let temp: Vec<u8> = value1
            .iter()
            .zip(value2.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        let expected = hex::decode("746865206b696420646f6e277420706c6179").unwrap();

        assert_eq!(temp, expected);
    }

    #[test]
    fn repeating_key_xor() {
        let key: Vec<u8> = Vec::from("ICE".to_string());
        let line1 = Vec::from("Burning 'em, if you ain't quick and nimble");
        println!("{:?}", line1.len());
        let mut cyphertext = Vec::with_capacity(line1.len());

        // iterate through plaintext
        line1.iter().enumerate().for_each(|(index, value)| {
            cyphertext.push(value ^ key[index % 3]);
        });

        println!("{}", hex::encode(cyphertext));
    }
}

mod aes_ecb_tests {
    #[test]
    fn decrypt_ecb_ciphertext() {
        use crate::set_one::aes_ecb::AesEcb128;
        use crate::utils::parse_file_base64;

        let ciphertext = parse_file_base64("src/set_one/1-7.txt");
        let key = "YELLOW SUBMARINE".as_bytes();

        let cipher = AesEcb128::new(key);

        let plaintext = cipher.decrypt(&ciphertext.as_slice());

        println!("PLAINTEXT:\n\n{}", String::from_utf8(plaintext).unwrap());
    }
}

#[allow(dead_code)]
pub mod aes_ecb {
    use aes::{
        cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
        Aes128, Block,
    };

    pub struct AesEcb128 {
        key: Block,
        cipher: Aes128,
    }

    impl AesEcb128 {
        pub fn new(key: &[u8]) -> Self {
            assert!(key.len() <= 16);

            let mut key_array = GenericArray::from([0u8; 16]);
            key_array.copy_from_slice(key);

            let cipher = Aes128::new(&key_array);

            AesEcb128 {
                key: key_array,
                cipher,
            }
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
            let encrypted_blocks = ciphertext.chunks(16);

            // allocate mutable buffer
            let mut plaintext = Vec::<Block>::with_capacity(encrypted_blocks.len());

            // fill buffer
            plaintext.extend(
                encrypted_blocks
                    .map(|block| Block::clone_from_slice(block))
                    .collect::<Vec<Block>>(),
            );

            // decrypt (parallelizable)
            self.cipher.decrypt_blocks(&mut plaintext);

            // flatten out of blocks, same length as the slice
            plaintext.into_iter().flatten().collect::<Vec<u8>>()
        }
    }
}
