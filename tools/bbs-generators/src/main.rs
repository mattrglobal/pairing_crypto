use clap::{Parser, ValueEnum};
use pairing_crypto::bbs::ciphersuites::{
    bls12_381_g1_sha_256::create_generators as bls12_381_sha_256_create_generators,
    bls12_381_g1_shake_256::create_generators as bls12_381_shake_256_create_generators,
};
use std::path::PathBuf;

use serde_derive::Serialize;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Ciphersuite {
    Bls12381Sha256,
    Bls12381Shake256,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutputType {
    Print,
    File,
}

#[allow(non_snake_case)]
#[derive(Serialize, Debug, Clone)]
pub struct FixtureGenerators {
    pub P1: String,
    pub P2: String,
    pub Q1: String,
    pub MsgGenerators: Vec<String>,
}

#[derive(Parser)]
struct Cli {
    // Count of generators to be generated.
    #[clap(short, long, value_parser, default_value = "10")]
    num_of_generators: usize,
    // Ciphersuite.
    #[clap(short, long, value_parser, default_value = "bls12381-shake256")]
    ciphersuite: Ciphersuite,
    // Output type.
    #[clap(short, long, value_parser, default_value = "print")]
    output_type: OutputType,
    // The path to the file to write the generators.
    #[clap(short, long, parse(from_os_str), default_value = "generators.json", value_hint = clap::ValueHint::DirPath)]
    file_name: PathBuf,
}

fn main() {
    let Cli {
        num_of_generators,
        ciphersuite,
        output_type,
        file_name,
    } = Cli::parse();

    let generators = match ciphersuite {
        Ciphersuite::Bls12381Sha256 => {
            bls12_381_sha_256_create_generators(num_of_generators, None)
        }
        Ciphersuite::Bls12381Shake256 => {
            bls12_381_shake_256_create_generators(num_of_generators, None)
        }
    }
    .unwrap();

    let fixture = FixtureGenerators {
        P1: hex::encode(generators[0].clone()),
        P2: hex::encode(generators[1].clone()),
        Q1: hex::encode(generators[2].clone()),
        MsgGenerators: generators
            .iter()
            .skip(3)
            .map(|g| hex::encode(g))
            .collect(),
    };

    match output_type {
        OutputType::Print => print_generators(&fixture),
        OutputType::File => write_generators_to_file(&fixture, file_name),
    }
}

fn print_generators(generators: &FixtureGenerators) {
    println!("{:#?}", generators);
}

fn write_generators_to_file(
    generators: &FixtureGenerators,
    file_name: PathBuf,
) {
    std::fs::write(
        file_name,
        serde_json::to_string_pretty(&generators).unwrap(),
    )
    .unwrap();
}
