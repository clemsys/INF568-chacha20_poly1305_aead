use chacha20_poly1305_aead::lib::poly1305::poly1305_check;
use clap::{arg, command, value_parser};

fn main() {
    // deal with command line arguments
    let matches = command!()
        .arg(
            arg!([KEY] "32-byte key, given as a 64-character hexadecimal string")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([FILE] "name of the file to authenticate")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .arg(
            arg!([TAG] "16-byte authenticator tag, given as a 32-character hexadecimal string")
                .required(true)
                .value_parser(value_parser!(String)),
        )
        .get_matches();

    // extract r and s from key
    let key = matches.get_one::<String>("KEY").unwrap();
    let filename = matches.get_one::<String>("FILE").unwrap();
    let auth_tag = matches.get_one::<String>("TAG").unwrap();

    let check = poly1305_check(filename, key, auth_tag);

    print!("{}", if check { "ACCEPT" } else { "REJECT" });
}
