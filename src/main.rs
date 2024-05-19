use clap::{Parser, Subcommand};
use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write, copy, stdin, stdout};
use std::path::PathBuf;
use scytale::hash::Hash;
use scytale::hash::sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256
};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// input file (defaults to stdin)
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// output file (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>
}

#[derive(Subcommand)]
enum Command {
    /// compute a SHA2-224 digest
    Sha224,

    /// compute a SHA2-256 digest
    Sha256,

    /// compute a SHA2-384 digest
    Sha384,

    /// compute a SHA2-512 digest
    Sha512,

    /// compute a SHA2-512/224 digest
    Sha512_224,

    /// compute a SHA2-512/256 digest
    Sha512_256,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Sha224) =>
            do_hash::<Sha224>(cli.input, cli.output),
        Some(Command::Sha256) =>
            do_hash::<Sha256>(cli.input, cli.output),
        Some(Command::Sha384) =>
            do_hash::<Sha384>(cli.input, cli.output),
        Some(Command::Sha512) =>
            do_hash::<Sha512>(cli.input, cli.output),
        Some(Command::Sha512_224) =>
            do_hash::<Sha512_224>(cli.input, cli.output),
        Some(Command::Sha512_256) =>
            do_hash::<Sha512_256>(cli.input, cli.output),
        None => Ok(())
    }
}

fn do_hash<H: Hash + Write>(inpath: Option<PathBuf>, outpath: Option<PathBuf>)
    -> Result<(), Box<dyn Error>>
{
    let mut input: BufReader<Box<dyn Read>> = BufReader::new(
        match inpath {
           Some(path) => Box::new(File::open(path)?),
           None => Box::new(stdin())
        }
    );

    let mut output: BufWriter<Box<dyn Write>> = BufWriter::new(
       match outpath {
           Some(path) => Box::new(File::open(path)?),
           None => Box::new(stdout())
       }
    );

    let mut hash = H::new();
    copy(&mut input, &mut hash)?;
    let digest = hash.finalize();
    writeln!(&mut output, "{}", hex::encode(digest.as_ref()))?;

    Ok(())
}
