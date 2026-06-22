use std::io::{self, Read, Write};

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("error: failed to read stdin");
        std::process::exit(1);
    }
    match apkprobe_rules::run(&input) {
        Ok(out) => {
            let _ = io::stdout().write_all(out.as_bytes());
            let _ = io::stdout().write_all(b"\n");
        }
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(1);
        }
    }
}
