use hash_slinging_slasher::sha2;

fn main() {
    let output = sha2::SHA256::hash(&mut b"hello world".as_slice())
        .iter()
        .map(|v| format!("{:02X}", v))
        .collect::<String>();
    println!("Output Buffer:\n{}", output);
}
