extern crate env_logger;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate quote;
extern crate tl_lang_syn;
extern crate tl_lang_rust_interop;


use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use quote::ToTokens;


mod error {
    error_chain! {
        foreign_links {
            Io(::std::io::Error);
            SetLogger(::log::SetLoggerError);
            TlLangSynParse(::tl_lang_syn::error::ParseError);
            Var(::std::env::VarError);
        }
    }
}


const TL_SCHEMA_DIR:       &'static str = "./tl";
const TL_SCHEMA_LIST_FILE: &'static str = "./tl/tl-schema-list.txt";
const RUST_SCHEMA_FILE:    &'static str = "./schema.rs";

fn collect_input() -> error::Result<String> {
    let mut tl_files = BufReader::new(File::open(TL_SCHEMA_LIST_FILE)?).lines().filter_map(|line| {
        match line {
            Ok(ref line) if line.trim_left().starts_with("//") => None,  // This line is a comment
            Ok(filename) => Some(Ok(Path::new(TL_SCHEMA_DIR).join(filename))),
            Err(e) => Some(Err(e)),  // Do not ignore errors
        }
    }).collect::<io::Result<Vec<PathBuf>>>()?;

    tl_files.sort();
    debug!("Files detected: {:?}", &tl_files);
    println!("cargo:rerun-if-changed={}", TL_SCHEMA_LIST_FILE);

    let mut input = String::new();
    for tl_file in tl_files {
        File::open(&tl_file)?.read_to_string(&mut input)?;
        println!("cargo:rerun-if-changed={}", tl_file.to_string_lossy());
    }

    Ok(input)
}

fn main() -> error::Result<()> {
    env_logger::try_init()?;

    let input = collect_input()?;
    let parse_tree = tl_lang_syn::parse_file_str(&input)?;
    let schema = tl_lang_rust_interop::Schema::from_tl_file(&parse_tree);
    let code = schema.into_token_stream().to_string();
    debug!("Code size: {} bytes", code.len());

    let rust_schema_file = Path::new(&env::var("OUT_DIR")?).join(RUST_SCHEMA_FILE);
    File::create(&rust_schema_file)?.write_all(code.as_str().as_bytes())?;
    debug!("Successful write to {:?}", rust_schema_file);

    Command::new("rustfmt")
        .arg(&rust_schema_file)
        .status()?;

    Ok(())
}
