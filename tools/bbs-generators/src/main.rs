use clap::{Parser, ValueEnum};
use pairing_crypto::bbs::ciphersuites::{
    bls12_381_g1_sha_256::create_generators as bls12_381_sha_256_create_generators,
    bls12_381_g1_shake_256::create_generators as bls12_381_shake_256_create_generators,
};
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
};

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

    match output_type {
        OutputType::Print => print_generators(&generators),
        OutputType::File => write_generators_to_file(&generators, file_name),
    }
}

fn print_generators(generators: &[Vec<u8>]) {
    println!("G1 BP = {}", hex::encode(generators[0].clone()));
    generators.iter().skip(1).enumerate().for_each(|(i, g)| {
        println!("G_{} = {}", i + 1, hex::encode(g));
    });
}

fn write_generators_to_file(generators: &[Vec<u8>], file_name: PathBuf) {
    let path = env::current_dir().unwrap();
    let file_path = path.join(file_name);
    let file = File::create(file_path).unwrap();

    let result: Vec<String> =
        generators.iter().map(|item| hex::encode(item)).collect();

    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &result).unwrap();
    writer.flush().unwrap();
}
