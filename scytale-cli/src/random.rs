//! `scytale random`: bytes from the system-seeded generator.

use std::path::PathBuf;

use clap::Args;
use scytale::Random;
use scytale::random::{CtrDrbg, MAX_REQUEST};
use zeroize::Zeroizing;

use crate::fail::Result;
use crate::io;

#[derive(Args)]
pub struct RandomArgs {
    /// How many bytes
    count: usize,
    /// Write the raw bytes rather than hex
    #[arg(long)]
    binary: bool,
    /// Write to this file, created readable by the owner alone
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(args: RandomArgs) -> Result<()> {
    let mut rng = CtrDrbg::from_system()?;
    let mut bytes = Zeroizing::new(vec![0u8; args.count]);
    // The generator caps one request; a larger one is several.
    for chunk in bytes.chunks_mut(MAX_REQUEST) {
        rng.fill(chunk)?;
    }
    let mut out = io::output(args.out.as_deref(), true)?;
    io::write(&mut *out, &bytes, !args.binary)
}
