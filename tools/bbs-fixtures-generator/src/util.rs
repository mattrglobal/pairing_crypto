use serde::Serialize;
use std::path::PathBuf;

pub fn save_test_vector_to_file<T>(
    fixture: &T,
    output_dir: &PathBuf,
    output_sub_dir: &str,
    test_vector_file_name: &str,
) where
    T: Serialize,
{
    let mut test_vector_file_path = output_dir.clone();
    test_vector_file_path.extend(&[output_sub_dir, test_vector_file_name]);

    std::fs::write(
        test_vector_file_path,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}
