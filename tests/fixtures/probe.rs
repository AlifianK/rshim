#![cfg_attr(gui, windows_subsystem = "windows")]

use std::{
    env, fs,
    io::{self, Read},
    os::windows::ffi::OsStrExt,
    thread,
    time::Duration,
};

fn main() {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.first().and_then(|arg| arg.to_str()) {
        Some("sleep") => {
            fs::write(&args[1], std::process::id().to_string()).unwrap();
            thread::sleep(Duration::from_secs(30));
        }
        Some("exit") => std::process::exit(args[1].to_str().unwrap().parse().unwrap()),
        Some("stdin") => {
            let mut input = String::new();
            io::stdin().read_to_string(&mut input).unwrap();
            print!("{input}");
            eprint!("stderr-ok");
        }
        Some("env") => {
            for name in &args[1..] {
                println!("{:?}", env::var_os(name));
            }
        }
        _ => {
            for arg in args {
                println!("{:04x?}", arg.encode_wide().collect::<Vec<_>>());
            }
        }
    }
}
