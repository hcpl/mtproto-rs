extern crate rustfmt;
extern crate tl_codegen;

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use rustfmt::Input;
use rustfmt::config::Config;


const TL_SCHEMA_DIR:       &'static str = "./tl";
const TL_SCHEMA_LIST_FILE: &'static str = "./tl/tl-schema-list.txt";
const RUST_SCHEMA_FILE:    &'static str = "./src/schema.rs";

fn collect_input() -> io::Result<String> {
    let mut tl_files = BufReader::new(File::open(TL_SCHEMA_LIST_FILE)?).lines().filter_map(|line| {
        match line {
            Ok(ref line) if line.starts_with("//") => None,  // This line is a comment
            Ok(filename) => Some(Ok(Path::new(TL_SCHEMA_DIR).join(filename))),
            Err(e) => Some(Err(e)),  // Do not ignore errors
        }
    }).collect::<io::Result<Vec<PathBuf>>>()?;

    tl_files.sort();
    println!("cargo:rerun-if-changed={}", TL_SCHEMA_LIST_FILE);

    let mut input = String::new();
    for tl_file in tl_files {
        File::open(&tl_file)?.read_to_string(&mut input)?;
        println!("cargo:rerun-if-changed={}", tl_file.to_string_lossy());
    }

    Ok(input)
}

fn run() -> io::Result<()> {
    let input = collect_input()?;
    let code = tl_codegen::generate_code_for(&input);
    File::create(RUST_SCHEMA_FILE)?.write_all(code.as_str().as_bytes())?;

    // Make output from `quote!`s human-readable
    let input = Input::File(PathBuf::from(RUST_SCHEMA_FILE));
    let config = Config::from_toml_path(Path::new("rustfmt.toml")).unwrap_or_else(|_| Config::default());

    if rustfmt::run(input, &config).has_no_errors() {
        Ok(())
    } else {
        let msg = format!("error while running `rustfmt` on {}", RUST_SCHEMA_FILE);
        Err(io::Error::new(io::ErrorKind::Other, msg))
    }
}

fn main() {
    run().unwrap()
}
