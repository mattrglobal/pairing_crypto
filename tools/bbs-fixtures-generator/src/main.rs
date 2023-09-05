use bbs_fixtures_generator::{FixtureGenInput, TestAsset};
use clap::Parser;

#[derive(Parser)]
struct Cli {
    // The path to the file to read the test assets
    #[clap(short = 'i', value_parser = clap::value_parser!(std::ffi::OsString), value_hint = clap::ValueHint::DirPath)]
    test_asset_file: std::path::PathBuf,
    // The path to the directory to write the fixture files
    #[clap(short = 'o', value_parser = clap::value_parser!(std::ffi::OsString), value_hint = clap::ValueHint::DirPath)]
    fixture_output_dir: std::path::PathBuf,
}

fn main() {
    let Cli {
        test_asset_file,
        fixture_output_dir,
    } = Cli::parse();

    let test_asset = {
        let test_asset = std::fs::read_to_string(test_asset_file).unwrap();
        serde_json::from_str::<TestAsset>(&test_asset).unwrap()
    };

    let fixture_gen_request: FixtureGenInput = test_asset.into();

    bbs_fixtures_generator::generate_fixtures(
        &fixture_gen_request,
        &fixture_output_dir,
    );
}
