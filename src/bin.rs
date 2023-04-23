use hash_slinging_slasher::SHA256;
use std::fs::File;
use std::io;

use argh::FromArgs;

const PROGNAME: &str = env!("CARGO_BIN_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

// General Notes on this file:
//
// The error handling in the functions below may look odd. It is currently
// implemented as such to mirror the behavior of GNU sha256sum. Almost all
// errors are non-critical (all remaining files will still be
// checksummed/verified) and the most important indicator of failure is the
// program's exit code. This is why errors are handled locally with
// `eprintf!()`s and the Result enum types are both ().

/// Compute and check SHA256 message digests
#[derive(FromArgs, Debug)]
struct CliArgs {
    /// file(s) to be read. If no file or "-" is specified, STDIN will be read.
    #[argh(positional, arg_name="FILE")]
    files: Vec<String>,

    /// read checksums from the FILEs and check them
    #[argh(switch, short='c')]
    checksum: bool,

    /// show version and exit
    #[argh(switch, short='V')]
    version: bool,
}

fn digest_file(path: String) -> io::Result<String> {
    let file: Box<dyn io::Read> = if path == "-" {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(&path)?)
    };

    Ok(SHA256::hash(file)
         // Convert vector of bytes to hex string
         .iter()
         .map(|v| format!("{:02x}", v))
         .collect::<String>())
}

// Take the path to a checksum file, open it, parse it, and verify each line in the file.
// A failure of one of the files is not critical (other files should still be checksummed),
// but in that case an Err(()) will be returned from this function so the caller can distinguish
// that there should be a non-zero exit code.
//
// This is a CLI-only function so it will write directly to STDOUT and STDERR
fn validate_checksum_file(checksum_path: String) -> Result<(), ()> {
    let mut file: Box<dyn io::Read> = if checksum_path == "-" {
        Box::new(io::stdin())
    } else {
        let file_obj = match File::open(&checksum_path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("Failed to open file '{}' with error {}", checksum_path, error);
                return Err(());
            }
        };
        Box::new(file_obj)
    };

    let mut checksum_lines = String::new();

    match file.read_to_string(&mut checksum_lines) {
        Ok(_) => (),
        Err(error) => {
          eprintln!("Failed to read file '{}' with error {}", checksum_path, error);
          return Err(());
        }
    }

    let mut did_error = false;

    for (idx, line) in checksum_lines.lines().enumerate() {
        let elements = line.splitn(2, "  ").collect::<Vec<&str>>();
        if elements.len() != 2 {
            eprintln!("Failed to parse line {}:{} due to malformed line: Missing filename", checksum_path, idx + 1);
            did_error = true;
            continue;
        }

        let expected_checksum = elements[0];
        let file_path = elements[1];

        // Ensure that hash length is correct (the multiplication by 2 is necessary because these
        // are ASCII-hex encoded bytes)
        if expected_checksum.len() != SHA256::HASH_LEN * 2 {
            eprintln!("Failed to parse line {}:{} due to malformed line: Invalid hash length", checksum_path, idx + 1);
            did_error = true;
            continue;
        }

        let tmp_digest = digest_file(String::from(file_path));
        let digest = match tmp_digest {
            Ok(result) => result,
            Err(error) => {
                eprintln!("Error reading {}: {}", file_path, error);
                did_error = true;
                continue;
            },
        };
        if digest == expected_checksum {
            println!("{}: OK", file_path);
        } else {
            println!("{}: FAILED", file_path);
            did_error = true;
            continue;
        }
    }

    if did_error {
        return Err(());
    }

    Ok(())
}

fn main() {
    let mut args: CliArgs = argh::from_env();

    if args.version {
        println!("{} {}", PROGNAME, VERSION);
        std::process::exit(0);
    }

    // If there are no specified files, default to STDIN
    match args.files.is_empty() {
        true => args.files.push("-".to_string()),
        false => ()
    };

    let mut has_errored = false;
    for file_path in args.files {
        if args.checksum {
            match validate_checksum_file(file_path) {
                Ok(_) => (),
                Err(_) => {
                    has_errored = true;
                }
            }
        } else {
            let digest = digest_file(String::from(&file_path));
            match digest {
                Ok(result) => println!("{}  {}", result, &file_path),
                Err(error) => {
                    println!("Error reading {}: {}", file_path, error);
                    has_errored = true;
                },
            };
        }
    }

    if has_errored {
        std::process::exit(1);
    }
}
