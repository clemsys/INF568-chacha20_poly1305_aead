use assert_cmd::Command;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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

    let mut cmd = Command::cargo_bin("poly1305_check")?;

    cmd.args([key.to_string(), filename.to_string(), auth_tag])
        .assert()
        .success()
        .stdout("ACCEPT");
    Ok(())
}

#[test]
fn accept_short_text_rfc() -> TestResult {
    let mut cmd = Command::cargo_bin("poly1305_check")?;

    cmd.args([
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        "tests/samples/poly1305/short-text.txt",
        "a8061dc1305136c6c22b8baf0c0127a9",
    ])
    .assert()
    .success()
    .stdout("ACCEPT");
    Ok(())
}

#[test]
fn reject_short_text_rfc() -> TestResult {
    let mut cmd = Command::cargo_bin("poly1305_check")?;

    cmd.args([
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        "tests/samples/poly1305/short-text.txt",
        "a8061dc1305136c6e22b8baf0c0127a9",
    ])
    .assert()
    .success()
    .stdout("REJECT");
    Ok(())
}

#[test]
fn accpt_short_text() -> TestResult {
    run(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        "tests/samples/poly1305/short-text.txt",
    )
}

#[test]
fn correct_short_binary() -> TestResult {
    run(
        "9288a877ee833095bc19d8e47494a203b39fd22f0049de7f208c73f3774c5be4",
        "tests/samples/poly1305/short-binary.bin",
    )
}

#[test]
fn accept_urandoms() -> TestResult {
    let binding = std::fs::read_to_string("tests/samples/poly1305/urandom_keys").unwrap();
    let keys: Vec<&str> = binding.lines().collect();
    for (i, key) in keys.iter().enumerate() {
        run(key, &format!("tests/samples/poly1305/urandom{}", i)).unwrap();
    }
    Ok(())
}
