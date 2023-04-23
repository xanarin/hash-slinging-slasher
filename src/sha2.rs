use std::io::prelude::*;
use std::io::BufReader;

pub struct SHA256;
impl SHA256 {
    /// Number of bytes in a digest for this algorithm
    pub const HASH_LEN: usize = 32;

    /// Initial values to seed state - defined by RFC6234
    const IV: [u32; 8] = [
        // These are the first 32 bits of the fractional parts of the square roots of the
        // first 8 primes 2..19, according to Wikipedia
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Calculate a SHA256 digest of some finite input data
    pub fn hash<T: std::io::Read>(input: T) -> Vec<u8> {
        // We can return the result of the underlying SHA256 implementation directly since we
        // don't need to truncate the resulting hash (unlike SHA224)
        _SHA256::hash(SHA256::IV, input)
    }
}

pub struct SHA224;
impl SHA224 {
    /// Number of bytes in a digest for this algorithm
    pub const HASH_LEN: usize = 28;

    /// Initial values to seed state - defined by RFC6234
    const IV: [u32; 8] = [
        // The second 32 bits of the fractional parts of the square roots of the 9th through
        // 16th primes 23..53, according to Wikipedia
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];

    pub fn hash<T: std::io::Read>(input: T) -> Vec<u8> {
        let mut full_hash = _SHA256::hash(SHA224::IV, input);
        assert_eq!(full_hash.len(), SHA256::HASH_LEN,
                   "Returned hash had {} bits when {} were expected",
                   full_hash.len() * 8, SHA256::HASH_LEN);
        full_hash.truncate(SHA224::HASH_LEN);
        full_hash
    }
}



/// This is the underlying implementation of SHA256 that is intended to only be used by the public
/// structs in this module.
struct _SHA256 {
    pub state: [u32; 8],
}
impl _SHA256 {
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

    // Function name taken from RFC6234
    fn ssig0(input: u32) -> u32 {
        input.rotate_right(7) ^ input.rotate_right(18) ^ input.wrapping_shr(3)
    }

    // Function name taken from RFC6234
    fn ssig1(input: u32) -> u32 {
        input.rotate_right(17) ^ input.rotate_right(19) ^ input.wrapping_shr(10)
    }

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

    // Takes a 64-byte (512-bit) chunk of data to be hashed
    fn update_state(self: &mut _SHA256, input: &[u8; 64]) {
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
            message_schedule[i] = _SHA256::ssig1(message_schedule[i - 2])
                .wrapping_add(message_schedule[i - 7])
                .wrapping_add(_SHA256::ssig0(message_schedule[i - 15]))
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
                .wrapping_add(_SHA256::ROUND_CONSTANTS[i])
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
    fn calculate_hash(self: &_SHA256) -> Vec<u8> {
        // Concat state (in BE) into final output
        let mut output: Vec<u8> = vec![];
        for i in 0..self.state.len() {
            output.extend(&self.state[i].to_be_bytes());
        }
        output
    }

    pub fn hash<T: std::io::Read>(init_values: [u32; 8], input: T) -> Vec<u8> {
        let mut reader = BufReader::new(input);
        let mut read_buf: [u8; 64] = [0; 64];
        let mut data_size = 0;

        // Initialize hash state 
        let mut hasher = _SHA256 {
            state: init_values,
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

                _SHA256::prepare_input(&mut trailer_buf, data_size);

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


#[cfg(test)]
mod tests {
    use super::{SHA224, SHA256};
    use std::io::Cursor;

    ///////////////////
    // SHA-224 tests //
    ///////////////////
    #[test]
    fn sha224_empty() {
        assert_eq!(
            SHA224::hash(Cursor::new(vec![])),
            hex::decode("D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")
                .unwrap()
        );
    }

    #[test]
    fn sha224_hello_world() {
        assert_eq!(
            SHA224::hash(Cursor::new(b"hello world".to_vec())),
            hex::decode("2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B")
                .unwrap()
        );
    }

    #[test]
    fn sha224_large() {
        // These are all printable ASCII characters
        let ascii_input = r##"!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"##.as_bytes();
        assert_eq!(
            SHA224::hash(Cursor::new(ascii_input)),
            hex::decode("A078924D5C0DFE0AD9B1F402FB7A9428ABCF522D6E7DBB64E7C32644").unwrap()
        );

        let one_million_a = (0..1_000_000).map(|_| b'a').collect::<Vec<u8>>();
        assert_eq!(
            SHA224::hash(Cursor::new(one_million_a)),
            hex::decode("20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67")
                .unwrap()
        );
    }

    #[test]
    fn sha224_nist() {
        // These are the official SHA vectors from NIST:
        // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
        assert_eq!(
            SHA224::hash(Cursor::new(b"abc".to_vec())),
            hex::decode("23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7").unwrap()
        );

        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec();
        assert_eq!(
            SHA224::hash(Cursor::new(input)),
            hex::decode("75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525").unwrap()
        );
    }

    ///////////////////
    // SHA-256 tests //
    ///////////////////
    #[test]
    fn sha256_empty() {
        assert_eq!(
            SHA256::hash(Cursor::new(vec![])),
            hex::decode("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
                .unwrap()
        );
    }

    #[test]
    fn sha256_hello_world() {
        assert_eq!(
            SHA256::hash(Cursor::new(b"hello world".to_vec())),
            hex::decode("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9")
                .unwrap()
        );
    }

    #[test]
    fn sha256_large() {
        // These are all printable ASCII characters
        let ascii_input = r##"!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"##.as_bytes();
        assert_eq!(
            SHA256::hash(Cursor::new(ascii_input)),
            hex::decode("4E50F468889F027F80ED19724951A2F576FA61E04C27DBE9EC988F506B591FE5").unwrap()
        );

        let one_million_a = (0..1_000_000).map(|_| b'a').collect::<Vec<u8>>();
        assert_eq!(
            SHA256::hash(Cursor::new(one_million_a)),
            hex::decode("CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0")
                .unwrap()
        );
    }

    #[test]
    fn sha256_nist_vectors() {
        // These are the official SHA vectors from NIST:
        // http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
        assert_eq!(
            SHA256::hash(Cursor::new(b"abc".to_vec())),
            hex::decode("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD").unwrap()
        );

        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec();
        assert_eq!(
            SHA256::hash(Cursor::new(input)),
            hex::decode("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1").unwrap()
        );
    }
}
