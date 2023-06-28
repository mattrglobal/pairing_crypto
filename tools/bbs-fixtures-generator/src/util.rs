use super::model::CaseName;
use serde::Serialize;
use std::path::PathBuf;

pub(crate) fn save_test_vector<T>(fixture: &mut T, output_file: &PathBuf)
where
    T: Serialize + CaseName,
{
    // set case name
    fixture.derive_case_name();

    std::fs::write(
        output_file,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}
