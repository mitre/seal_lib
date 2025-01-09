use anyhow::{bail, Result};
use seal_lib::parse_logs;
use std::{fs, path::PathBuf};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct ILFChecker {
    #[structopt(long, short, parse(from_os_str))]
    ilf_file: PathBuf,
}

fn main() -> Result<()> {
    let ILFChecker { ilf_file } = ILFChecker::from_args();
    let file_name = ilf_file.clone();
    let file_contents = match fs::read_to_string(ilf_file) {
        Ok(c) => c,
        Err(e) => bail!("Could not read file {}. Error: {}", file_name.display(), e),
    };
    match parse_logs(file_contents.as_str()) {
        Ok((_leftover, logs)) => {
            println!("Parsed {} logs!", logs.len());
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
