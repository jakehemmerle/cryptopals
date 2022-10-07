// This is an isolated module for cracking rotating-key xor ciphers

pub use repeating_key_xor::*;

pub mod repeating_key_xor {
    use std::collections::HashMap;
    use utils::*;

    /// This iterates through the blocks and uses the hamming distance to guess the key length
    pub fn guess_key_length(ciphertext: &[u8], key_length_upper_bound: u8) -> Vec<u8> {
        use itertools::Itertools;
        // create map for key length to hamming distance
        let mut distance: HashMap<usize, f32> = HashMap::new();

        // iterate through possible key lengths
        for key_length in 2..key_length_upper_bound as usize {
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

        let mut top_lengths: Vec<u8> = vec![];
        for _ in 0..3 {
            top_lengths.push(*sorted_normalized_weights.next().unwrap().0 as u8);
        }
        top_lengths
    }

    /// Brute forces the ciphertext based on the provided ciphertext and guessed key length.
    /// Returns the most likely plaintext and key based on lowest delta_from_english
    pub fn brute_force_ciphertext(ciphertext: &[u8], key_length: u8) -> (Vec<u8>, Vec<u8>) {
        // split ciphertext into key_length number of columns (each column will be xor'd with the same byte)
        let chunks = ciphertext_to_chunks(ciphertext, key_length);
        let columns: Vec<Vec<u8>> = transpose(chunks.clone());

        // solve each column as a single key xor with lowest hamming distance between them
        let potential_key: Vec<u8> = columns
            
            .iter()
            .map(|column| guess_xord_key(column.as_slice()))
            .collect();

        // decrypt the ciphertext using the potential key
        let mut potential_plaintext = Vec::with_capacity(ciphertext.len());
        for (index, letter) in ciphertext.iter().enumerate() {
            potential_plaintext.push(letter ^ potential_key[index % key_length as usize] as u8);
        }

        (potential_plaintext, potential_key)
    }

    /// Returns the number of bits that are different between two byte slices.
    pub fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> usize {
        assert!(bytes1.len() == bytes2.len());
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

    /// Returns the most likely character of a single key xor'd ciphertext based on the frequency of letters
    fn guess_xord_key(ciphertext: &[u8]) -> u8 {
        // new map storing char to english word score
        let mut char_score = HashMap::with_capacity(255);
        let mut decrypted_ciphertext = HashMap::with_capacity(255);

        // insert char and score distance of unedited ciphertext
        let mut highest_score_key = 0u8;
        let mut highest_score = delta_from_english(ciphertext);
        char_score.insert(highest_score_key, highest_score);

        // insert key and score of ciphertext xor every key 'a' through 'Z'
        for potential_key in 0..=255_u8 {
            let potential_plaintext = ciphertext
                .to_owned()
                .iter()
                .map(|letter| (*letter as u8 ^ potential_key))
                .collect::<Vec<u8>>();

            decrypted_ciphertext.insert(potential_key, potential_plaintext.clone());

            let potential_key_score = delta_from_english(potential_plaintext.as_slice());
            if potential_key_score < highest_score {
                highest_score_key = potential_key;
                highest_score = potential_key_score;
            }

            char_score.insert(potential_key, potential_key_score);
        }

        highest_score_key
    }

    /// statistical likelihood that a potential ciphertext is english based on letter frequency;
    /// lower means higher likelyhood of ciphertext being the plaintext
    fn delta_from_english(potential_plaintext_column: &[u8]) -> f32 {
        let mut overall_delta = 0.0f32;
        let mut char_count = HashMap::with_capacity(26);

        // get frequency of each letter
        for letter in potential_plaintext_column {
            let letter_count = char_count.entry(*letter).or_insert(0f32);
            *letter_count += 1f32;
        }

        // normalize count
        for count in char_count.values_mut() {
            *count /= (potential_plaintext_column.len()) as f32;
        }

        // compute and return delta
        for (letter, frequency) in char_count.drain() {
            let mut single_char_delta = character_frequency(letter) - frequency;

            if single_char_delta < 0f32 {
                single_char_delta *= -1f32;
            }

            overall_delta += single_char_delta
        }

        overall_delta
    }

    #[test]
    fn hamming_distance_works() {
        let string1 = "this is a test";
        let string2 = "wokka wokka!!!";

        let bytes1 = string1.as_bytes();
        let bytes2 = string2.as_bytes();

        assert_eq!(hamming_distance(bytes1, bytes2), 37);
    }

    /// Returns table of character frequencies for the English language.
    /// TODO move this into the function its used in
    fn character_frequency(byte: u8) -> f32 {
        let char_freq: HashMap<u8, f32> = HashMap::from([
            (32, 0.167_564_44),
            (101, 0.086_102_29),
            (116, 0.063_296_5),
            (97, 0.061_255_4),
            (110, 0.055_037_037),
            (105, 0.054_806_262),
            (111, 0.054_190_442),
            (115, 0.051_886_5),
            (114, 0.051_525_03),
            (108, 0.032_181_926),
            (100, 0.031_889_48),
            (104, 0.026_192_373),
            (99, 0.025_002_688),
            (10, 0.019_578_06),
            (117, 0.019_247_776),
            (109, 0.018_140_173),
            (112, 0.017_362_094),
            (102, 0.015_750_347),
            (103, 0.012_804_66),
            (46, 0.011_055_184_5),
            (121, 0.010_893_687),
            (98, 0.010_346_445),
            (119, 0.009_565_83),
            (44, 0.008_634_492),
            (118, 0.007_819_144),
            (48, 0.005_918_945_7),
            (107, 0.004_945_712),
            (49, 0.004_937_789_4),
            (83, 0.003_089_691_5),
            (84, 0.003_070_106_5),
            (67, 0.002_987_392_7),
            (50, 0.002_756_238),
            (56, 0.002_552_781),
            (53, 0.002_526_921_2),
            (65, 0.002_477_483),
            (57, 0.002_442_242_6),
            (120, 0.002_306_414_5),
            (51, 0.002_186_558_7),
            (73, 0.002_091_041_8),
            (45, 0.002_076_717_3),
            (54, 0.001_919_909_8),
            (52, 0.001_838_527_2),
            (55, 0.001_824_329_5),
            (77, 0.001_813_491_2),
            (66, 0.001_738_700_2),
            (34, 0.001_575_427_7),
            (39, 0.001_507_862_2),
            (80, 0.001_389_084),
            (69, 0.001_293_820_7),
            (78, 0.001_275_883_5),
            (70, 0.001_220_297_3),
            (82, 0.001_103_737_4),
            (68, 0.001_092_772_3),
            (85, 0.001_042_637),
            (113, 0.001_008_537_4),
            (76, 0.001_004_480_9),
            (71, 0.000_931_021),
            (74, 0.000_881_456_13),
            (72, 0.000_875_244_7),
            (79, 0.000_821_052_9),
            (87, 0.000_804_827),
            (106, 0.000_617_596_03),
            (122, 0.000_576_270_86),
            (47, 0.000_519_607_16),
            (60, 0.000_441_076_64),
            (62, 0.000_440_442_82),
            (75, 0.000_380_800_2),
            (41, 0.000_331_425_46),
            (40, 0.000_330_791_63),
            (86, 0.000_255_620_37),
            (89, 0.000_251_944_2),
            (58, 0.000_120_362_776),
            (81, 0.000_100_017_096),
            (90, 0.000_086_199_776),
            (88, 0.000_065_727_33),
            (59, 0.000_007_415_716),
            (63, 0.000_004_626_899_7),
            (127, 0.000_003_105_727_3),
            (94, 0.000_002_218_376_7),
            (38, 0.000_002_028_23),
            (43, 0.000_001_521_172_5),
        ]);

        *char_freq.get(&byte).unwrap_or(&0f32)
    }

    #[test]
    fn test_delta_from_english() {
        let potential_plaintext = String::from("The very first well-documented description of a polyalphabetic cipher was by Leon Battista Alberti around 1467 and used a metal");
        println!(
            "plaintext: {}",
            delta_from_english(potential_plaintext.as_bytes())
        );

        let not_likely_plaintext = String::from("Dlc fipi jgbwr gijv-hmmykorroh bowabmndmmx sd k tmvcyvtfkfcdma mmnrip geq lc Josl Lerdmqde Yvfcbxg kvmerb 1467 krb ewcn e koxyv");
        println!(
            "not plaintext: {}",
            delta_from_english(not_likely_plaintext.as_bytes())
        );

        let not_plaintext = String::from("Cmm znwg jrwax fjtp-mtkyvjvxni libhzmyyqsw tn e yttcjqxljgmxrh kmymmv ffa fh Qmsw Gixcnaxj Ftfnwbm jwwywi 1467 irm zaim f uicft");
        println!(
            "not plaintext: {}",
            delta_from_english(not_plaintext.as_bytes())
        );
    }
    pub mod utils {
        /// Splits ciphertext into slices of size `key_length`, leaving the last slice unpadded.
        pub fn ciphertext_to_chunks(ciphertext: &[u8], key_length: u8) -> Vec<&[u8]> {
            let mut chunks: Vec<&[u8]> = vec![];
            for i in 0..(ciphertext.len() / key_length as usize) {
                chunks
                    .push(&ciphertext[(i * key_length as usize)..((i + 1) * key_length as usize)]);
            }
            chunks
        }

        /// Transpose Chunks -> .collect_vec() to a Vec of vecs
        pub fn transpose<T>(v: Vec<&[T]>) -> Vec<Vec<T>>
        where
            T: Clone,
        {
            let mut transposed = vec![vec![]; v[0].len()];

            for row in v {
                for (i, col) in row.iter().enumerate() {
                    transposed[i].push(col.clone());
                }
            }

            transposed
        }
    }
}
