pub fn hexdump(input: &Vec<u8>) -> String {
    let mut result = String::from("");
    for i in 0..(input.len() + input.len() % 16) / 16 {
        let mut line: String = String::from(format!("{:06X}: ", i * 16));
        // Write the hexdump
        for j in 0..16 {
            // If in range, print a character. If not, print a space
            line = format!("{}{}", line, 
                input.get(i * 16 + j).map_or_else(|| String::from("   "), |v| format!("{:02X} ", v))
            );
            if j == 7 {
                line.push_str(" ");
            }
        };
        // Write the ASCII
        line.push_str("  |");
        for j in 0..16 {
            if i * 16 + j < input.len() {
                let cur_char: char = input[i * 16 + j] as char;
                if cur_char.is_ascii_alphanumeric() {
                    line.push(cur_char);
                } else {
                    line.push('.');
                }
            } else {
                line.push(' ');
            }
        };
        line.push_str("|\n");
        result.push_str(&line);
    };
    result
}

pub fn byte_to_bin_str(in_byte: u8) -> String {
    let mut result = String::from("");
    for i in 0..8 {
        result = format!("{}{}", result, (in_byte >> (7 - i)) & 0x1);
    }
    result
}

pub fn bindump(input: &Vec<u8>) -> String {
    let mut result = String::from("");
    let byte_count = input.len();
    for i in 0..byte_count / 4 {
        let mut line = "".to_string();
        for j in 0..4 {
            line = format!("{} {}", line, input.get(i * 4 + j).map_or_else(
                    || " ".to_string(),
                    |v| byte_to_bin_str(*v)));
        };
        // Remove the leading space
        line.remove(0);
        line.push('\n');
        result.push_str(&line);
    };
    result
}
