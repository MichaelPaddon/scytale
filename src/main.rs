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

#[derive(Clone, Default, ValueEnum)]
enum Format {
        /// a Base64 encoded string
        Base64,

        /// a hexadecimal encoded string
        Hex,

        /// raw bytes
        #[default]
        Raw
}

#[derive(Args)]
struct Input {
    /// input file (defaults to stdin)
    #[arg(short, long)]
    input: Option<PathBuf>,
}

#[derive(Args)]
struct Output {
    /// output file (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct Key {
    /// key string
    #[arg(long)]
    key: Option<String>,

    /// key input file
    #[arg(long)]
    key_input: Option<PathBuf>,
}

#[derive(Args)]
struct KeyFormat {
    /// key format
    #[arg(long)]
    key_format: Option<Format>,
}

#[derive(Subcommand)]
enum Command {
    /// compute a hash
    Hash {
        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,

        /// name of hash algorithm
        algorithm: Option<String>
    },

    /// compute a mac
    Mac {
        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,

        #[command(flatten)]
        key: Key,

        #[command(flatten)]
        key_format: KeyFormat,

        /// name of mac algorithm
        algorithm: Option<String>,
    }
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

fn input_arg(path: Option<PathBuf>) -> InputArg {
    path.map_or(InputArg::default(), |x| InputArg::from_arg(x))
}

fn output_arg(path: Option<PathBuf>) -> OutputArg {
    path.map_or(OutputArg::default(), |x| OutputArg::from_arg(x))
}

fn decode(encoded: &[u8], format: Format) 
    -> Result<Vec<u8>, Box<dyn Error>>
{
    let decoded = match format {
        Format::Base64 => BASE64_STANDARD.decode(encoded)?,
        Format::Hex => hex::decode(encoded)?,
        Format::Raw => encoded.to_vec()
    };
    Ok(decoded)
}

fn make_key(key: &Key, key_format: &KeyFormat)
    -> Result<Vec<u8>, Box<dyn Error>>
{
    let encoded = if let Some(ref string) = key.key {
        string.clone()
    }
    else if let Some(ref path) = key.key_input {
        let input = InputArg::from_arg(path);
        input.read_to_string()?
    }
    else {
        panic!();
    };

    let format = key_format.key_format.clone().unwrap_or(Format::default());
    decode(encoded.as_bytes(), format)
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hash{input, output, algorithm}
            => hash_command(
                input_arg(input.input),
                output_arg(output.output),
                algorithm
            ),
        Command::Mac{input, output, key, key_format, algorithm}
            => mac_command(
                input_arg(input.input),
                output_arg(output.output),
                &make_key(&key, &key_format)?,
                algorithm
            )
    }
}
