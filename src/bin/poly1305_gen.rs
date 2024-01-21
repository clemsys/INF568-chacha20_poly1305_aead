use clap::{arg, command, value_parser};
use poly1305::lib::{le_string_from_integer, poly1305_gen};

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
        .get_matches();

    let key = matches.get_one::<String>("KEY").unwrap();
    let filename = matches.get_one::<String>("FILE").unwrap();

    print!("{}", le_string_from_integer(&poly1305_gen(filename, key)));
}
