mod dumper;
use crate::dumper::*;

mod sha2 {
    pub mod sha256 {
        use byteorder::{ByteOrder, BigEndian};
        use super::super::*;

        fn prepare_input(input: &mut Vec<u8>) {
            // Note: This function only works on byte-sized payloads and does not accept a number of
            // bits of data that is not evenly divisible by 8

            let input_len = input.len();
            // Determine the amount of padding needed for input. The 8 is for the extra bit that we
            // have to add, and the 64 is for the u64 representing the original input length.
            let padding_len = (512 - (((input_len * 8) + 8 + 64) % 512)) / 8;

            // The 7 in this line comes from the other 7 bits after the 0b1 we append. In practice, we
            // just treat that byte like a u8 because we know that the original data will always be
            // byte-sized and byte-aligned
            println!("We need {} bits of padding", padding_len * 8 + 7);

            // Write single bit in the MSB (but actually write an entire u8)
            input.push(1 << 7);
            // Write the padding bytes
            input.extend(vec![0; padding_len]);

            // Add original size of data as u64
            let mut size_bytes = [0; 8];
            BigEndian::write_u64(&mut size_bytes, input_len as u64 * 8);
            input.extend_from_slice(&size_bytes);
        }

        // Function name taken from RFC6234
        fn ssig0(input: u32) -> u32 {
            input.rotate_right(7) ^ input.rotate_right(18) ^ input.wrapping_shr(3)
        }

        // Function name taken from RFC6234
        fn ssig1(input: u32) -> u32 {
            input.rotate_right(17) ^ input.rotate_right(19) ^ input.wrapping_shr(10)
        }

        pub fn compute(input: &Vec<u8>) -> [u8; 32] {
            // todo: Can we replace this with a COW data structure so we don't have to duplicate
            // data?
            let mut in_data = input.clone();
            prepare_input(&mut in_data);

            if in_data.len() != 64 {
                panic!("in_data was {} bytes, whereas only 64 is supported", in_data.len())
            }

            // Initialize hash state (first 32 bits of the fractional parts of the square roots of
            // the first 8 primes 2..19)
            let mut state: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f,
            0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

            // Initialize round constants (first 32 bits of the fractional parts of the cube roots
            // of the first 64 primes 2..311)
            let k: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
            0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
            0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
            0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
            0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
            0xa4506ceb, 0xbef9a3f7, 0xc67178f2];


            // From this point on, this should happen for each 512 bit (64 byte) chunk of input
            {
                // 1 - Compute message schedule
                // 1a - copy data from input
                let mut message_schedule: [u32; 64] = [0; 64];
                for i in 0..16 {
                    message_schedule[i] = u32::from(in_data[i*4]) << 24 |
                        u32::from(in_data[i*4 + 1]) << 16 |
                        u32::from(in_data[i*4 + 2]) << 8 |
                        u32::from(in_data[i*4 + 3]);
                }

                // 1b - calculate the remainder of the schedule
                for i in 16..64 {
                    // Wrapping add is used here because these values are allowed to overflow and wrap
                    // back around
                    message_schedule[i] = ssig1(message_schedule[i-2])
                            .wrapping_add(message_schedule[i-7])
                            .wrapping_add(ssig0(message_schedule[i-15]))
                            .wrapping_add(message_schedule[i - 16]);
                }

                // Initialize working values
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                // Compression function main loop
                for i in 0..64 {
                    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                    let ch = (e & f) ^ ((!e) & g);
                    let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(message_schedule[i]);
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

                state[0] = state[0].wrapping_add(a);
                state[1] = state[1].wrapping_add(b);
                state[2] = state[2].wrapping_add(c);
                state[3] = state[3].wrapping_add(d);
                state[4] = state[4].wrapping_add(e);
                state[5] = state[5].wrapping_add(f);
                state[6] = state[6].wrapping_add(g);
                state[7] = state[7].wrapping_add(h);
            }

            // Concat state (in BE) into final output
            let mut output: [u8; 32] = [0; 32];
            for i in 0..state.len() {
                let val = state[i].to_be_bytes();
                for j in 0..4 {
                    output[i*4 + j] = val[j];
                }
            }
            output
        }
    }
}


fn main() {
    let input: Vec<u8> = String::from("hello world").chars().map(|c| c as u8).collect();
    println!("Input Buffer:\n{}", hexdump(&input));

    let output = sha2::sha256::compute(&input);
    let output_str = output.iter().map(|v| format!("{:02X}", v)).collect::<String>();
    println!("Output Buffer:\n{}", output_str);
}
