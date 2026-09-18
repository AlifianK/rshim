mod shims;
mod windows;

fn main() {
    // Drop process and job handles before exiting.
    std::process::exit(run());
}

fn run() -> i32 {
    let shim = match shims::Shim::init() {
        Ok(shim) => shim,
        Err(error) => {
            eprintln!("Error while loading shim: {error}");
            return 1;
        }
    };
    let launch = match windows::launch(&shim) {
        Ok(launch) => launch,
        Err(error) => {
            eprintln!(
                "Error while spawning target program `{}`: {error}",
                shim.target_path.display()
            );
            return 2;
        }
    };
    let windows::Launch::Foreground(process) = launch else {
        return 0;
    };
    match process.wait() {
        Ok(code) => code as i32,
        Err(error) => {
            eprintln!(
                "Error while waiting for target program `{}`: {error}",
                shim.target_path.display()
            );
            3
        }
    }
}
