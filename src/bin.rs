use hash_slinging_slasher::sha2;


fn main() {
    let input = &b"hello world".to_vec();
    let output = sha2::SHA256::from(&input).unwrap().hash();
    let output_str = output.iter().map(|v| format!("{:02X}", v)).collect::<String>();
    println!("Output Buffer:\n{}", output_str);
}
