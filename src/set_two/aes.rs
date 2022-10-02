pub use self::aes::*;

#[allow(dead_code)]
pub mod aes {
    pub use ::aes::Block;
    use ::aes::{
        cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
        Aes128,
    };

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
        CBC(Block),
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

                    // zip ciphertext with output
                    for (ciphertext_block, out_block) in ciphertext.iter().zip(out.iter_mut()) {
                        // copy ciphertext block to output
                        out_block.copy_from_slice(ciphertext_block);

                        // decrypt output
                        self.cipher.decrypt_block(out_block);

                        // xor output with prev block/iv
                        for (out, prev) in out_block.iter_mut().zip(prev_block.iter()) {
                            *out ^= *prev;
                        }
                        // update prev block
                        prev_block = *ciphertext_block;
                    }
                }
                CipherMode::ECB => {
                    // copy ciphertext into output
                    for (ciphertext_block, out) in ciphertext.iter().zip(out.iter_mut()) {
                        out.copy_from_slice(ciphertext_block);
                    }
                    // parallel decrypt
                    self.cipher.decrypt_blocks(out);
                }
            }
        }

        /// Encrypts a slice of Blocks into a provided output buffer
        /// UNTESTSED
        pub fn encrypt(&self, plaintext: &[Block], out: &mut [Block]) {
            assert!(out.len() >= plaintext.len());

            match self.cipher_mode {
                CipherMode::CBC(iv) => {
                    let mut prev_block = Block::from(iv);

                    for (plaintext_block, out_block) in plaintext.iter().zip(out).into_iter() {
                        // copy plaintext block to buffer
                        out_block.copy_from_slice(plaintext_block);

                        // xor buffer with prev block/iv
                        for (out, prev) in out_block.iter_mut().zip(prev_block.iter()) {
                            *out ^= *prev;
                        }

                        // encrypt the block
                        self.cipher.encrypt_block(out_block);

                        // update prev block
                        prev_block = *out_block;
                    }
                }
                CipherMode::ECB => {
                    // copy plaintext into output
                    for (plaintext_block, out_block) in
                        plaintext.iter().zip(out.iter_mut()).into_iter()
                    {
                        out_block.copy_from_slice(plaintext_block);
                    }

                    // parallel encrypt
                    self.cipher.encrypt_blocks(out);
                }
            }
        }
    }
}
