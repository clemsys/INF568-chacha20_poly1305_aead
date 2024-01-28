use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TESTS_DIR: &str = "tests/samples/chacha20";

fn run(key: &str, filename: &str) -> TestResult {
    let openssl_cmd = Command::new("openssl")
        .args([
            "dgst",
            "-mac",
            "poly1305",
            "-macopt",
            &format!("hexkey:{}", key),
            &format!("{}", filename),
        ])
        .output()?;

    let openssl_cmd_stdout = String::from_utf8(openssl_cmd.stdout)?;
    let mut auth_tag: String = openssl_cmd_stdout.split(" ").nth(1).unwrap().to_owned();
    auth_tag.retain(|c| !c.is_whitespace());

    let mut cmd = Command::cargo_bin("chacha20")?;

    cmd.args([key.to_string(), filename.to_string(), auth_tag])
        .assert()
        .success()
        .stdout("ACCEPT");
    Ok(())
}

#[test]
fn correct_sunscreen_encrypt() -> TestResult {
    let mut cmd = Command::cargo_bin("chacha20")?;

    cmd.args([
        &format!("{TESTS_DIR}/keyfile"),
        "000000000000004a00000000",
        &format!("{TESTS_DIR}/sunscreen.txt"),
        &format!("{TESTS_DIR}/my_ciphertext.bin"),
    ])
    .assert()
    .success();
    let result = std::fs::read(&format!("{TESTS_DIR}/my_ciphertext.bin"))?;
    std::fs::remove_file(&format!("{TESTS_DIR}/my_ciphertext.bin"))?;
    let expected = std::fs::read(&format!("{TESTS_DIR}/ciphertext.bin"))?;
    assert_eq!(result, expected);
    Ok(())
}

#[test]
fn correct_sunscreen_decrypt() -> TestResult {
    let mut cmd = Command::cargo_bin("chacha20")?;

    cmd.args([
        &format!("{TESTS_DIR}/keyfile"),
        "000000000000004a00000000",
        &format!("{TESTS_DIR}/ciphertext.bin"),
        &format!("{TESTS_DIR}/my_sunscreen.txt"),
    ])
    .assert()
    .success();
    let result = std::fs::read(&format!("{TESTS_DIR}/my_sunscreen.txt"))?;
    std::fs::remove_file(&format!("{TESTS_DIR}/my_sunscreen.txt"))?;
    let expected = std::fs::read(&format!("{TESTS_DIR}/sunscreen.txt"))?;
    assert_eq!(result, expected);
    Ok(())
}
