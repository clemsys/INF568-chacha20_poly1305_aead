use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const SAMPLES_DIR: &str = "tests/samples/poly1305";

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
    let mut expected_tag: String = openssl_cmd_stdout.split(" ").nth(1).unwrap().to_owned();
    expected_tag.retain(|c| !c.is_whitespace());

    let mut cmd = Command::cargo_bin("poly1305_gen")?;

    cmd.args([key.to_string(), filename.to_string()])
        .assert()
        .success()
        .stdout(expected_tag);
    Ok(())
}

#[test]
fn correct_short_text_rfc() -> TestResult {
    let mut cmd = Command::cargo_bin("poly1305_gen")?;

    cmd.args([
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        &format!("{SAMPLES_DIR}/short-text.txt"),
    ])
    .assert()
    .success()
    .stdout("a8061dc1305136c6c22b8baf0c0127a9");
    Ok(())
}

#[test]
fn correct_short_text() -> TestResult {
    run(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        &format!("{SAMPLES_DIR}/short-text.txt"),
    )
}

#[test]
fn correct_short_binary() -> TestResult {
    run(
        "9288a877ee833095bc19d8e47494a203b39fd22f0049de7f208c73f3774c5be4",
        &format!("{SAMPLES_DIR}/short-binary.bin"),
    )
}

#[test]
fn correct_urandoms() -> TestResult {
    let binding = std::fs::read_to_string(&format!("{SAMPLES_DIR}/urandom_keys")).unwrap();
    let keys: Vec<&str> = binding.lines().collect();
    for (i, key) in keys.iter().enumerate() {
        run(key, &format!("{SAMPLES_DIR}/urandom{i}")).unwrap();
    }
    Ok(())
}
