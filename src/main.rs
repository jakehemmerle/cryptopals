use std::env;
use std::fs;

pub mod set1 {
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
    fn single_xor_cipher() {
        use std::collections::HashMap;

        let letter_frequency: HashMap<char, f32> = HashMap::from([
            ('a', 0.08167),
            ('b', 0.01492),
            ('c', 0.02782),
            ('d', 0.04253),
            ('e', 0.12702),
            ('f', 0.02228),
            ('g', 0.02015),
            ('h', 0.06094),
            ('i', 0.06966),
            ('j', 0.00153),
            ('k', 0.00772),
            ('l', 0.04025),
            ('m', 0.02406),
            ('n', 0.06749),
            ('o', 0.07507),
            ('p', 0.01929),
            ('q', 0.00095),
            ('r', 0.05987),
            ('s', 0.06327),
            ('t', 0.09056),
            ('u', 0.02758),
            ('v', 0.00978),
            ('w', 0.02360),
            ('x', 0.00150),
            ('y', 0.01974),
            ('z', 0.00074),
        ]);

        let original_string = String::from_utf8(
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap(),
        )
        .unwrap();

        let mut xord_strings: Vec<String> = vec![];

        for i in 0..255 {
            let mut xord_string = String::new();
            for c in original_string.chars() {
                xord_string.push((c as u8 ^ i) as char);
            }
            xord_strings.push(xord_string);
        }

        let weighted_mapping: Vec<(f32, String)> = xord_strings
            .iter()
            .map(|s| {
                let char_count: HashMap<char, u8> =
                    s.chars()
                        .filter(|c| c.is_alphabetic())
                        .fold(HashMap::new(), |mut acc, c| {
                            *acc.entry(c.to_ascii_lowercase()).or_insert(0) += 1;
                            acc
                        });

                let delta: f32 = char_count
                    .iter()
                    .map(|(c, count)| {
                        let expected_count = letter_frequency.get(c).unwrap() * s.len() as f32;
                        let delta = expected_count - (*count as f32 / s.len() as f32);
                        // r^2?
                        delta * delta
                    })
                    .sum();

                (delta, s.to_string())
            })
            .collect();

        // print weighted mapping
        for (score, s) in weighted_mapping {
            println!("{}: {}", score, s);
        }

        // xord_strings.iter().for_each(|x| println!("{}", x));
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

mod repeating_key_xor {
    use itertools::Itertools;

    #[test]
    fn hamming_distance_demo() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";

        let bytes1 = string1.as_bytes();
        let bytes2 = string2.as_bytes();

        assert_eq!(hamming_distance(bytes1, bytes2), 37);
    }

    fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> usize {
        bytes1.iter().zip(bytes2.iter()).fold(0, |acc, (a, b)| {
            let mut distance: usize = 0;
            let mut xor = a ^ b;
            while xor > 0 {
                if xor & 1 == 1 {
                    distance += 1;
                }
                xor >>= 1;
            }
            acc + distance
        })
    }

    // fn hamming_distance_of_

    #[test]
    fn find_key_length() {
        use itertools::{Chunks, Itertools};
        use std::collections::HashMap;
        use std::fs;

        // parse file
        let file = fs::read_to_string("6.txt").expect("Should have been able to read the file");
        let ciphertext = base64::decode(file.replace("\n", "")).unwrap();

        // create map for key length to hamming distance
        let mut distance: HashMap<usize, f32> = HashMap::new();

        // iterate through possible key lengths
        for key_length in 2..40 as usize {
            let mut chunks: Vec<Vec<u8>> = ciphertext
                .chunks(key_length)
                .into_iter()
                .map(|x| x.to_vec())
                .collect();

            // make sure chunks are the same size and theres an even count
            if chunks.last().unwrap().len() != key_length {
                chunks.pop();
            }
            if chunks.len() % 2 != 0 {
                chunks.pop();
            }

            // po
            let dist_entry = distance.entry(key_length).or_insert(0 as f32);

            // calculate hamming distance: ITERTOOLS IS COOL
            for (chunk1, chunk2) in chunks.iter().tuples() {
                let hamm_dist = hamming_distance(chunk1, chunk2);
                // divide by key length to normalize
                *dist_entry += hamm_dist as f32 / key_length as f32;
            }

            // divide the sum by chunks to normalize
            *dist_entry /= chunks.len() as f32;
        }

        // sort and print
        let mut sorted_normalized_weights = distance
            .iter()
            .sorted_by(|a, b| a.1.partial_cmp(b.1).unwrap());

        println!(
            "Most likely key length: {:?}",
            sorted_normalized_weights.next().unwrap()
        );
        println!("Other highest weights:");
        sorted_normalized_weights.for_each(|(a, b)| println!("{:?}: {:?}", a, b));
    }
}

/*
news:
public channels
- irc
- usenet

 */
