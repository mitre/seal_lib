/**
 * Copyright 2025 The MITRE Corporation

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

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
