use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SAMPLES_DIR: &str = "tests/samples/chacha20";

#[test]
fn correct_sunscreen_encrypt() -> TestResult {
    let mut cmd = Command::cargo_bin("chacha20")?;

    cmd.args([
        &format!("{SAMPLES_DIR}/keyfile"),
        "000000000000004a00000000",
        &format!("{SAMPLES_DIR}/sunscreen.txt"),
        &format!("{SAMPLES_DIR}/my_ciphertext.bin"),
    ])
    .assert()
    .success();
    let result = std::fs::read(&format!("{SAMPLES_DIR}/my_ciphertext.bin"))?;
    std::fs::remove_file(&format!("{SAMPLES_DIR}/my_ciphertext.bin"))?;
    let expected = std::fs::read(&format!("{SAMPLES_DIR}/ciphertext.bin"))?;
    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn correct_sunscreen_decrypt() -> TestResult {
    let mut cmd = Command::cargo_bin("chacha20")?;

    cmd.args([
        &format!("{SAMPLES_DIR}/keyfile"),
        "000000000000004a00000000",
        &format!("{SAMPLES_DIR}/ciphertext.bin"),
        &format!("{SAMPLES_DIR}/my_sunscreen.txt"),
    ])
    .assert()
    .success();
    let result = std::fs::read(&format!("{SAMPLES_DIR}/my_sunscreen.txt"))?;
    std::fs::remove_file(&format!("{SAMPLES_DIR}/my_sunscreen.txt"))?;
    let expected = std::fs::read(&format!("{SAMPLES_DIR}/sunscreen.txt"))?;
    assert_eq!(result, expected);
    Ok(())
}
