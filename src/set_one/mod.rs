// 1.6

mod aes_ecb;

mod repeating_key_xor_tests {
    /// This brute forces some dummy data
    #[test]
    fn brute_force_dummy_data() {
        use crate::repeating_key_xor::*;

        let ciphertext = hex::decode("1729316330212a223f6323262c363a63273b3b613e362c242625742c37313161202b24742f202d63253b246f740a6123222f2063353b6323316320362f2474372e742f282226613d2d613563253b332474332d352024742a2f740d181763363d372974092e3c2d6f740a66396331262635203a613236223f2a2f336332202c2a31276f7417293d30613d3061332c283a2461202c613626613563262626202063353d2e247a").unwrap();
        let key_lengths = guess_key_length(&ciphertext, 5);

        for key_length in key_lengths {
            let (plaintext, key) = brute_force_ciphertext(ciphertext.as_slice(), key_length);

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
        let ciphertext = base64::decode(file.replace('\n', "")).unwrap();
        let key_lengths = guess_key_length(&ciphertext, 40);

        let (plaintext, key) = brute_force_ciphertext(ciphertext.as_slice(), key_lengths[0]);

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
        use crate::set_one::aes_ecb::*;
        use crate::utils::parse_file_base64;

        let ciphertext = parse_file_base64("src/set_one/1-7.txt");
        let key = "YELLOW SUBMARINE".as_bytes();

        let cipher = AesEcb128::new(key);

        let plaintext = cipher.decrypt(ciphertext.as_slice());

        println!("PLAINTEXT:\n\n{}", String::from_utf8(plaintext).unwrap());
    }

    // 1-8
    #[test]
    fn find_ecb_ciphertext_from_many() {
        use crate::repeating_key_xor::hamming_distance;
        use itertools::Itertools;
        use std::fs;

        let mut ciphertexts = fs::read_to_string("src/set_one/1-8.txt")
            .unwrap()
            .split('\n')
            .collect::<Vec<&str>>()
            .into_iter()
            .map(|line| hex::decode(line).unwrap())
            .collect::<Vec<Vec<u8>>>();

        // get rid of last, empty line
        ciphertexts.pop();

        // break each ciphertext into 16 byte blocks and print the hamming distance between each block
        for blocksize in [16usize, 32, 48, 64, 80].into_iter() {
            let mut hamming_distances = Vec::<(usize, f32)>::with_capacity(ciphertexts.len());

            for (index, ciphertext) in ciphertexts.iter().enumerate() {
                let blocks = ciphertext
                    .chunks_exact(blocksize)
                    .collect_vec()
                    .into_iter()
                    .combinations(2)
                    .collect::<Vec<Vec<&[u8]>>>();
                let mut distance: f32 = 0f32;

                let blocks_len = blocks.len();

                for combination in blocks {
                    distance +=
                        hamming_distance(combination[0], combination[1]) as f32 / blocksize as f32;
                }

                hamming_distances.push((index, distance as f32 / blocks_len as f32));
            }

            hamming_distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

            let mut hamming_distances = hamming_distances.into_iter();

            let (line, hamming_distance) = hamming_distances.next().unwrap();
            println!(
                "blocksize: {}\nmost likely line number: {}\nweighted hamming distance of blocks: {}",
                blocksize,
                line,
                hamming_distance
            );
            println!("blocks:");
            for block in ciphertexts[line].chunks_exact(blocksize) {
                println!("{}", hex::encode(block));
            }
            println!("\n");

            let (line, hamming_distance) = hamming_distances.next().unwrap();
            println!("next highest weighted line info:");
            println!(
                "blocksize: {}\nline number: {}\nweighted hamming distance of blocks: {}",
                blocksize, line, hamming_distance
            );
            println!("blocks:");
            for block in ciphertexts[line].chunks_exact(blocksize) {
                println!("{}", hex::encode(block));
            }
            println!("\n");
        }
    }
}
