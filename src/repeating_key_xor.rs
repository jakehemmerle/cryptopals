// This is an isolated module for cracking rotating-key xor ciphers

pub use repeating_key_xor::{brute_force_ciphertext, guess_key_length};

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
            .clone()
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
    fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> usize {
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
        let mut highest_score = delta_from_english(ciphertext.into());
        char_score.insert(highest_score_key, highest_score);

        // insert key and score of ciphertext xor every key 'a' through 'Z'
        for potential_key in 0..=255 as u8 {
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
            (32, 0.167564443682168),
            (101, 0.08610229517681191),
            (116, 0.0632964962389326),
            (97, 0.0612553996079051),
            (110, 0.05503703643138501),
            (105, 0.05480626188138746),
            (111, 0.0541904405334676),
            (115, 0.0518864979648296),
            (114, 0.051525029341199825),
            (108, 0.03218192615049607),
            (100, 0.03188948073064199),
            (104, 0.02619237267611581),
            (99, 0.02500268898936656),
            (10, 0.019578060965172565),
            (117, 0.019247776378510318),
            (109, 0.018140172626462205),
            (112, 0.017362092874808832),
            (102, 0.015750347191785568),
            (103, 0.012804659959943725),
            (46, 0.011055184780313847),
            (121, 0.010893686962847832),
            (98, 0.01034644514338097),
            (119, 0.009565830104169261),
            (44, 0.008634492219614468),
            (118, 0.007819143740853554),
            (48, 0.005918945715880591),
            (107, 0.004945712204424292),
            (49, 0.004937789430804492),
            (83, 0.0030896915651553373),
            (84, 0.0030701064687671904),
            (67, 0.002987392712176473),
            (50, 0.002756237869045172),
            (56, 0.002552781042488694),
            (53, 0.0025269211093936652),
            (65, 0.0024774830020061096),
            (57, 0.002442242504945237),
            (120, 0.0023064144740073764),
            (51, 0.0021865587546870337),
            (73, 0.0020910417959267183),
            (45, 0.002076717421222119),
            (54, 0.0019199098857390264),
            (52, 0.0018385271551164353),
            (55, 0.0018243295447897528),
            (77, 0.0018134911904778657),
            (66, 0.0017387002075069484),
            (34, 0.0015754276887500987),
            (39, 0.0015078622753204398),
            (80, 0.00138908405321239),
            (69, 0.0012938206232079082),
            (78, 0.0012758834637326799),
            (70, 0.001220297284016159),
            (82, 0.0011037374385216535),
            (68, 0.0010927723198318497),
            (85, 0.0010426370083657518),
            (113, 0.00100853739070613),
            (76, 0.0010044809306127922),
            (71, 0.0009310209736100016),
            (74, 0.0008814561018445294),
            (72, 0.0008752446473266058),
            (79, 0.0008210528757671701),
            (87, 0.0008048270353938186),
            (106, 0.000617596049210692),
            (122, 0.0005762708620098124),
            (47, 0.000519607185080999),
            (60, 0.00044107665296153596),
            (62, 0.0004404428310719519),
            (75, 0.0003808001912620934),
            (41, 0.0003314254660634964),
            (40, 0.0003307916441739124),
            (86, 0.0002556203680692448),
            (89, 0.00025194420110965734),
            (58, 0.00012036277683200988),
            (81, 0.00010001709417636208),
            (90, 0.00008619977698342993),
            (88, 0.00006572732994986532),
            (59, 0.00000741571610813331),
            (63, 0.000004626899793963519),
            (127, 0.0000031057272589618137),
            (94, 0.0000022183766135441526),
            (38, 0.0000020282300466689395),
            (43, 0.0000015211725350017046),
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
