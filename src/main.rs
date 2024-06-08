use base64::prelude::{Engine as _, BASE64_STANDARD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use patharg::{InputArg, OutputArg};
use std::error::Error;
use std::io;
use std::io::Write;
use std::path::PathBuf;
use scytale::hash;
use scytale::mac;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command
}

#[derive(Clone, ValueEnum)]
enum Format {
        /// a Base64 encoded string
        Base64,

        /// a hexadecimal encoded string
        Hex,

        /// raw bytes
        Raw
}

#[derive(Args)]
struct Input {
    /// input file (defaults to stdin)
    #[arg(short, long)]
    #[arg(value_parser = clap::value_parser!(InputArg))]
    #[arg(default_value_t)]
    input: InputArg,
}

#[derive(Args)]
struct Output {
    /// output file (defaults to stdout)
    #[arg(short, long)]
    #[arg(value_parser = clap::value_parser!(OutputArg))]
    #[arg(default_value_t)]
    output: OutputArg,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Key {
    /// key string
    #[arg(long)]
    key: Option<String>,

    /// key file
    #[arg(long)]
    #[arg(value_parser = clap::value_parser!(InputArg))]
    key_file: Option<InputArg>,
}

#[derive(Args)]
struct KeyFormat {
    /// key format
    #[arg(long)]
    #[arg(default_value = "raw")]
    key_format: Format,
}

#[derive(Subcommand)]
enum Command {
    /// compute a hash function
    Hash {
        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,

        /// name of hash function
        algorithm: Option<String>
    },

    /// compute a MAC function
    Mac {
        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,

        #[command(flatten)]
        key: Key,

        #[command(flatten)]
        key_format: KeyFormat,

        /// name of MAC function
        algorithm: Option<String>,
    }
}

fn decode(encoded: &[u8], format: &Format) 
    -> Result<Vec<u8>, Box<dyn Error>>
{
    let decoded = match format {
        Format::Base64 => BASE64_STANDARD.decode(encoded)?,
        Format::Hex => hex::decode(encoded)?,
        Format::Raw => encoded.to_vec()
    };
    Ok(decoded)
}

fn hash_command(
    input: InputArg,
    output: OutputArg,
    algorithm: Option<String>
) -> Result<(), Box<dyn Error>> {
    match algorithm {
        Some(algorithm) => {
            let mut h = hash::from_name(&algorithm)?;
            let mut reader = input.open()?;
            io::copy(&mut reader, &mut h)?;
            let mut writer = output.create()?;
            writeln!(&mut writer, "{}", hex::encode(h.finalize()))?;
        },
        None => {
            for name in hash::list() {
                println!("{}", name)
            }
        }
    };
    Ok(())
}

fn mac_command(
    input: InputArg,
    output: OutputArg,
    key: &[u8],
    algorithm: Option<String>
) -> Result<(), Box<dyn Error>> {
    match algorithm {
        Some(algorithm) => {
            let mut m = mac::from_name(&algorithm, key)?;
            let mut reader = input.open()?;
            io::copy(&mut reader, &mut m)?;
            let mut writer = output.create()?;
            writeln!(&mut writer, "{}", hex::encode(m.finalize()))?;
        },
        None => {
            for name in mac::list() {
                println!("{}", name)
            }
        }
    };
    Ok(())
}

fn make_key(key: &Key, key_format: &KeyFormat)
    -> Result<Vec<u8>, Box<dyn Error>>
{
    let encoded = if let Some(ref string) = key.key {
        string.clone()
    }
    else if let Some(ref input) = key.key_file {
        input.read_to_string()?
    }
    else {
        panic!();
    };

    decode(encoded.as_bytes(), &key_format.key_format)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hash{input, output, algorithm}
            => hash_command(
                input.input,
                output.output,
                algorithm
            ),
        Command::Mac{input, output, key, key_format, algorithm}
            => mac_command(
                input.input,
                output.output,
                &make_key(&key, &key_format)?,
                algorithm
            )
    }
}
