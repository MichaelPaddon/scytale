use clap::{Args, Parser, Subcommand};
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

#[derive(Args)]
struct InputOption {
    /// input file (defaults to stdin)
    #[arg(short, long)]
    input: Option<PathBuf>,
}

#[derive(Args)]
struct OutputOption {
    /// output file (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// compute a hash
    Hash {
        #[command(flatten)]
        input: InputOption,

        #[command(flatten)]
        output: OutputOption,

        /// name of hash algorithm
        algorithm: Option<String>
    },

    /// compute a mac
    Mac {
        #[command(flatten)]
        input: InputOption,

        #[command(flatten)]
        output: OutputOption,

        /// name of hash algorithm
        #[clap(requires_all = ["key"])]
        algorithm: Option<String>,
 
        /// name of hash algorithm
        key: Option<String>
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hash{input, output, algorithm}
            => hash_command(input.input, output.output, algorithm),
        Command::Mac{input, output, algorithm, key}
            => mac_command(input.input, output.output, algorithm, key)
    }
}

fn hash_command(
    inpath: Option<PathBuf>,
    outpath: Option<PathBuf>,
    algorithm: Option<String>
) -> Result<(), Box<dyn Error>> {
    let input = inpath.map_or(InputArg::default(),
        |x| InputArg::from_arg(x));
    let output = outpath.map_or(OutputArg::default(),
        |x| OutputArg::from_arg(x));

    match algorithm {
        Some(name) => {
            let mut h = hash::from_name(&name)?;
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
    inpath: Option<PathBuf>,
    outpath: Option<PathBuf>,
    algorithm: Option<String>,
    key: Option<String>
) -> Result<(), Box<dyn Error>> {
    match algorithm {
        Some(name) => {
            let input = inpath.map_or(InputArg::default(),
                |x| InputArg::from_arg(x));
            let output = outpath.map_or(OutputArg::default(),
                |x| OutputArg::from_arg(x));
            let mut m = mac::from_name(&name, key.unwrap().as_bytes())?;
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
