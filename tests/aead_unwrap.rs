use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AEAD_SAMPLES_DIR: &str = "tests/samples/aead";

#[test]
fn correct_sunscreen_wrap() -> TestResult {
    let mut cmd = Command::cargo_bin("aead_unwrap")?;

    let expected_stdout: String =
        std::fs::read_to_string(&format!("{AEAD_SAMPLES_DIR}/sunscreen.txt")).unwrap();

    cmd.args([
        &format!("{AEAD_SAMPLES_DIR}/keyfile"),
        "070000004041424344454647",
        &format!("{AEAD_SAMPLES_DIR}/aad"),
        &format!("{AEAD_SAMPLES_DIR}/ciphertext.bin"),
        "1ae10b594f09e26a7e902ecbd0600691",
    ])
    .assert()
    .success()
    .stdout(expected_stdout);
    Ok(())
}
