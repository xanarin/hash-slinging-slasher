use hash_slinging_slasher::sha2;
use std::fs::File;
use std::io;

use clap::Parser;


fn digest_file(path: String) -> io::Result<String> {
    let file: Box<dyn io::Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&path)?)
    };

    Ok(sha2::SHA256::hash(file)
         // Convert vector of bytes to hex string
         .iter()
         .map(|v| format!("{:02x}", v))
         .collect::<String>())
}

#[derive(Parser)]
#[command(author, version, about = "sha256sum replacement")]
struct Cli {
    /// File(s) to be read. If no file or "-" is specified, STDIN will be read.
    #[arg(value_name = "FILE")]
    files: Vec<String>,

    /// End each output line with NUL, not newline
    #[arg(short, long)]
    zero: bool,

    // TODO: Implement checksum options
    // Checksum options
    /// Read checksums from the FILEs and check them
    #[arg(short, long)]
    check: bool,

    /// (When checksumming) don't fail or report status for missing files
    #[arg(long)]
    ignore_missing: bool,

    /// (When checksumming) don't print OK for each successfully verified file
    #[arg(long)]
    quiet: bool,

    /// (When checksumming) don't output anything, status code shows success
    #[arg(long)]
    status: bool,

    /// (When checksumming) exit non-zero for improperly formatted checksum lines
    #[arg(long)]
    strict: bool,

    /// (When checksumming) warn about improperly formatted checksum lines
    #[arg(long)]
    warn: bool,
}

fn main() {
    let mut args = Cli::parse();
    let mut has_errored = false;

    // If there are no specified files, default to STDIN
    match args.files.is_empty() {
        true => args.files.push("-".to_string()),
        false => ()
    };

    let line_delim = if args.zero {"\0"}  else {"\n"};
    
    for file_path in args.files {
        let digest = digest_file(String::from(&file_path));
        match digest {
            Ok(result) => print!("{}  {}{}", result, &file_path, line_delim),
            Err(error) => {
                print!("Error reading {}: {}{}", file_path, error, line_delim);
                has_errored = true;
            },
        };
    }

    if has_errored {
        std::process::exit(1);
    }
}
