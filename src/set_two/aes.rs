pub use self::aes::*;

#[allow(dead_code)]
pub mod aes {
    use std::io::Read;

    use ::aes::{
        cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
        Aes128, Block,
    };
    use aes::cipher::{generic_array::ArrayLength, typenum::U16, Key};
    use itertools::Itertools;

    pub const BLOCK_SIZE_BYTES: usize = 16;

    pub struct AES128 {
        key: Block,
        cipher: Aes128,
        cipher_mode: CipherMode,
    }

    pub enum CipherMode {
        /// Electronic Code Book
        ECB,
        /// CBC needs an initialization vector
        /// @John is it safe/required to store IV in the struct?
        CBC(GenericArray<u8, U16>),
    }

    impl AES128 {
        pub fn new(cipher_mode: CipherMode, key: &[u8]) -> Self {
            assert!(key.len() <= BLOCK_SIZE_BYTES);

            let mut key_array = GenericArray::from([0u8; BLOCK_SIZE_BYTES]);
            key_array.copy_from_slice(key);

            let cipher = Aes128::new(&key_array);

            AES128 {
                key: key_array,
                cipher,
                cipher_mode,
            }
        }

        /// This should write plaintext to a provided input buffer, not allocate mem itself
        pub fn decrypt(&self, ciphertext: &[Block], out: &mut [Block]) {
            assert_eq!(ciphertext.len(), out.len());

            match self.cipher_mode {
                CipherMode::CBC(iv) => {
                    let mut prev_block = GenericArray::from(iv.clone());
                    for (ciphertext_block, out) in ciphertext.iter().zip(out.iter_mut()) {
                        out.copy_from_slice(ciphertext_block);
                        self.cipher.decrypt_block(out);
                        for (out, (prev, enc_byte)) in out
                            .iter_mut()
                            .zip(prev_block.iter().zip(ciphertext_block.iter()))
                        {
                            *out ^= *prev;
                        }
                        prev_block = *ciphertext_block;
                    }
                }
                CipherMode::ECB => todo!(),
            }
        }

        // /// Encrypts a block based on what
        // pub fn encrypt(&self, plaintext: &[Block], out: &mut [Block]) {
        //     assert!(out.len() >= plaintext.len());

        //     match self.cipher_mode {
        //         CipherMode::CBC(iv) => {
        //             let mut prev_block = GenericArray::<u8, U16>::from(iv);
        //             let plaintext_chunks = plaintext
        //                 .chunks(BLOCK_SIZE_BYTES)
        //                 .map(|block| Block::from_slice(block))
        //                 .collect_vec();
        //             let out_chunks = out
        //                 .chunks_mut(BLOCK_SIZE_BYTES)
        //                 .map(|block| Block::from_mut_slice(block))
        //                 .collect_vec();

        //             for (plaintext_block, out_block) in
        //                 plaintext_chunks.iter().zip(out_chunks).into_iter()
        //             {
        //                 let mut in_block = GenericArray::<u8, U16>::clone_from_slice(&iv);
        //                 for (index, (in_byte, plaintext_byte)) in
        //                     in_block.iter_mut().zip(plaintext_block.iter()).enumerate()
        //                 {
        //                     *in_byte = plaintext_byte ^ prev_block.get(index).unwrap()
        //                 }

        //                 self.cipher.encrypt(&in_block, out_block);
        //                 prev_block.copy_from_slice(out_block);
        //             }
        //         }
        //         ECB => {
        //             let ciphertext_chunks = plaintext
        //                 .chunks(BLOCK_SIZE_BYTES)
        //                 .map(|block| Block::from(block))
        //                 .collect_vec();
        //             let out_chunks = out
        //                 .chunks_mut(BLOCK_SIZE_BYTES)
        //                 .map(|block| Block::from_mut_slice(block))
        //                 .collect_vec();

        //             self.cipher.decrypt_blocks_b2b(
        //                 ciphertext_chunks.as_slice(),
        //                 out_chunks.as_mut_slice(),
        //             );
        //         }
        //     }
        // }
    }
}
