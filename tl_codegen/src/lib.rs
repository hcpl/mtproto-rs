#[macro_use]
extern crate error_chain;
extern crate pom;
#[macro_use]
extern crate quote;
extern crate syn;
extern crate synom;


mod ast;
mod error;
mod generator;
mod parser;

pub use generator::generate_code_for;
