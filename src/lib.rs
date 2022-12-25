mod dumper;

pub mod sha2 {
    use std::io::prelude::*;
    use std::io::BufReader;

    pub struct SHA256 {
        pub state: [u32; 8],
    }

    impl Default for SHA256 {
        fn default() -> SHA256 {
            SHA256 {
                // These are the first 32 bits of the fractional parts of the square roots of the
                // first 8 primes 2..19, according to the SHA256 spec
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
            }
        }
    }

    impl SHA256 {
        // Number of bytes in a digest for this algorithm
        pub const HASH_LEN: usize = 32;

        // SHA256 round constants (first 32 bits of the fractional parts of the cube roots
        // of the first 64 primes 2..311)
        const ROUND_CONSTANTS: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        fn prepare_input(input: &mut Vec<u8>, bytes_read: usize) {
            // Note: This function only works on byte-sized payloads and does not accept a number of
            // bits of data that is not evenly divisible by 8

            // Determine the amount of padding needed for input. The 8 is for the extra bit that we
            // have to add, and the 64 is for the u64 representing the original input length.
            let padding_len = (512 - (((input.len() * 8) + 8 + 64) % 512)) / 8;

            // Write single bit in the MSB (but actually write an entire u8)
            input.push(1 << 7);
            // Write the padding bytes
            input.extend(vec![0; padding_len]);

            // Add original size of data as u64
            input.extend_from_slice(&(bytes_read as u64 * 8).to_be_bytes());
        }

        // Function name taken from RFC6234
        fn ssig0(input: u32) -> u32 {
            input.rotate_right(7) ^ input.rotate_right(18) ^ input.wrapping_shr(3)
        }

        // Function name taken from RFC6234
        fn ssig1(input: u32) -> u32 {
            input.rotate_right(17) ^ input.rotate_right(19) ^ input.wrapping_shr(10)
        }

        // Takes a 64-byte (512-bit) chunk of data to be hashed
        fn update_state(self: &mut SHA256, input: &[u8; 64]) {
            // 1 - Compute message schedule
            // 1a - copy data from input
            let mut message_schedule: [u32; 64] = [0; 64];
            for i in 0..16 {
                message_schedule[i] = u32::from(input[i * 4]) << 24
                    | u32::from(input[i * 4 + 1]) << 16
                    | u32::from(input[i * 4 + 2]) << 8
                    | u32::from(input[i * 4 + 3]);
            }

            // 1b - calculate the remainder of the schedule
            for i in 16..64 {
                // Wrapping add is used here because these values are allowed to overflow and wrap
                // back around
                message_schedule[i] = SHA256::ssig1(message_schedule[i - 2])
                    .wrapping_add(message_schedule[i - 7])
                    .wrapping_add(SHA256::ssig0(message_schedule[i - 15]))
                    .wrapping_add(message_schedule[i - 16]);
            }

            // Initialize working values
            let mut a = self.state[0];
            let mut b = self.state[1];
            let mut c = self.state[2];
            let mut d = self.state[3];
            let mut e = self.state[4];
            let mut f = self.state[5];
            let mut g = self.state[6];
            let mut h = self.state[7];

            // Compression function main loop
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(SHA256::ROUND_CONSTANTS[i])
                    .wrapping_add(message_schedule[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);

                // Reassign working variables
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }

            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }

        // Calculate hash from the current state
        fn calculate_hash(self: &SHA256) -> Vec<u8> {
            // Concat state (in BE) into final output
            let mut output: Vec<u8> = vec![];
            for i in 0..self.state.len() {
                output.extend(&self.state[i].to_be_bytes());
            }
            output
        }

        pub fn hash<T: std::io::Read>(input: T) -> Vec<u8> {
            let mut reader = BufReader::new(input);
            let mut read_buf: [u8; 64] = [0; 64];
            let mut data_size = 0;

            // Initialize hash state 
            let mut hasher: SHA256 = SHA256 {
                ..Default::default()
            };

            loop {
                // todo: replace this with better handling. Probably just a Result for this fn.
                // Should we handle the blocking case?
                let bytes_read = reader.read(&mut read_buf).expect("Failed to read bytes");
                data_size += bytes_read;

                if bytes_read < read_buf.len() {
                    // We were unable to read a whole 64 bytes, so we're at the end of the stream
                    // and we need to add the trailer. This may require a buffer larger than 64
                    // bytes, so we copy the data to a Vec here and then call update_state()
                    // multiple times (potentially)
                    let mut trailer_buf = read_buf[..bytes_read].to_vec();

                    SHA256::prepare_input(&mut trailer_buf, data_size);

                    // From this point on, this should happen for each 512 bit (64 byte) chunk of input
                    for block_count in 0..trailer_buf.len()/64 {
                        hasher.update_state(
                            &trailer_buf[block_count*64..][..64].try_into()
                                .expect("in_data's prepare length was not a multiple of 64"),
                        );
                    }
                    break;
                }

                hasher.update_state(
                    &read_buf,
                );
            }

            hasher.calculate_hash()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sha2;
    use std::io::Cursor;

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(vec![])),
            hex::decode("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
                .unwrap()
        );
    }

    #[test]
    fn sha256_hello_world() {
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(b"hello world".to_vec())),
            hex::decode("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9")
                .unwrap()
        );
    }

    #[test]
    fn sha256_large() {
        let alphabet_input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec();
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(alphabet_input)),
            hex::decode("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1").unwrap()
        );

        let one_million_a = (0..1_000_000).map(|_| b'a').collect::<Vec<u8>>();
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(one_million_a)),
            hex::decode("CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0")
                .unwrap()
        );
    }

    #[test]
    fn sha256_nist_vectors() {
        // These are the official SHA vectors from NIST:
        // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(b"abc".to_vec())),
            hex::decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").unwrap()
        );

        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec();
        assert_eq!(
            sha2::SHA256::hash(Cursor::new(input)),
            hex::decode("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1").unwrap()
        );
    }
}
