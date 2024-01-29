use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const AEAD_SAMPLES_DIR: &str = "tests/samples/aead";

#[test]
fn correct_sunscreen_wrap() -> TestResult {
    let mut cmd = Command::cargo_bin("aead_wrap")?;

    cmd.args([
        &format!("{AEAD_SAMPLES_DIR}/keyfile"),
        "070000004041424344454647",
        &format!("{AEAD_SAMPLES_DIR}/aad"),
        &format!("{AEAD_SAMPLES_DIR}/sunscreen.txt"),
        &format!("{AEAD_SAMPLES_DIR}/my_ciphertext.bin"),
    ])
    .assert()
    .success()
    .stdout("1ae10b594f09e26a7e902ecbd0600691");
    let result = std::fs::read(&format!("{AEAD_SAMPLES_DIR}/my_ciphertext.bin"))?;
    std::fs::remove_file(&format!("{AEAD_SAMPLES_DIR}/my_ciphertext.bin"))?;
    let expected = std::fs::read(&format!("{AEAD_SAMPLES_DIR}/ciphertext.bin"))?;
    assert_eq!(result, expected);
    Ok(())
}
