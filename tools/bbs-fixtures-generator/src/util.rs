use serde::Serialize;
use std::path::PathBuf;

pub fn save_test_vector_to_file<T>(fixture: &T, output_file: &PathBuf)
where
    T: Serialize,
{
    std::fs::write(
        output_file,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}
