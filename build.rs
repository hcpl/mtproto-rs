#[cfg(feature = "build-script-lib-rustfmt")]
extern crate rustfmt;
extern crate tl_codegen;

use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(feature = "build-script-lib-rustfmt")]
use rustfmt::Input;
#[cfg(feature = "build-script-lib-rustfmt")]
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

/// Unix `which` as Rust function
fn which<P: AsRef<Path>>(executable_name: P) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths).filter_map(|dir| {
            let full_path = dir.join(&executable_name);

            if full_path.is_file() {
                Some(full_path)
            } else {
                None
            }
        }).next()
    })
}

/// Make `quote~` output human-readable
fn format_quote_output() -> io::Result<()> {
    if let Some(path) = which("rustfmt") {
        // If installed already, use it to reduce the build time

        Command::new(path)
            .arg("--write-mode")
            .arg("overwrite")
            .arg(RUST_SCHEMA_FILE)
            .status()?;

        return Ok(());
    }

    #[cfg(feature = "build-script-lib-rustfmt")]
    {
        // Otherwise fetch and compile the library `rustfmt` if requested by the feature flag.
        // Why feature flag? Because compiling syntex is slow.

        let input = Input::File(PathBuf::from(RUST_SCHEMA_FILE));
        let config = Config::from_toml_path(Path::new("rustfmt.toml"))
            .unwrap_or_else(|_| Config::default());

        // Applying `rustfmt` is an optional step, so if it fails we should
        // at most print a message and move on
        if !rustfmt::run(input, &config).has_no_errors() {
            eprintln!("error while running `rustfmt` on {}; skipping the failure", RUST_SCHEMA_FILE);
        }
    }

    Ok(())
}


fn run() -> io::Result<()> {
    let input = collect_input()?;
    let code = tl_codegen::generate_code_for(&input);
    File::create(RUST_SCHEMA_FILE)?.write_all(code.as_str().as_bytes())?;

    format_quote_output()?;

    Ok(())
}

fn main() {
    run().unwrap()
}
