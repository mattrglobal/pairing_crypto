use bbs_bound_fixtures_generator::BoundFixtureGenInput;
use bbs_fixtures_generator::TestAsset;
use clap::Parser;

#[derive(Parser)]
struct Cli {
    #[clap(short = 'i',  parse(from_os_str), value_hint = clap::ValueHint::DirPath)]
    test_asset_file: std::path::PathBuf,
    // The path to the directory to write the fixture files
    #[clap(short = 'o', parse(from_os_str), value_hint = clap::ValueHint::DirPath)]
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

    let fixture_gen_request: BoundFixtureGenInput = test_asset.into();

    bbs_bound_fixtures_generator::generate_fixtures(
        &fixture_gen_request, 
        &fixture_output_dir)
}
