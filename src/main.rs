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
            BigEndian::write_u64(&mut size_bytes, input_len as u64);
            input.extend_from_slice(&size_bytes);
        }

        pub fn compute(input: &Vec<u8>) -> Vec<u8> {
            // todo: Can we replace this with a COW data structure so we don't have to duplicate
            // data?
            let mut in_data = input.clone();
            prepare_input(&mut in_data);
            println!("Prepared input:\n{}", bindump(&in_data));

            in_data
        }
    }
}


fn main() {
    let input: Vec<u8> = String::from("hello world").chars().map(|c| c as u8).collect();
    println!("Input Buffer:\n{}", hexdump(&input));

    let output = sha2::sha256::compute(&input);
    println!("Output Buffer:\n{}", hexdump(&output));
}
