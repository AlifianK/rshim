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
    let process = match windows::launch(&shim) {
        Ok(process) => process,
        Err(error) => {
            eprintln!(
                "Error while spawning target program `{}`: {error}",
                shim.target_path.display()
            );
            return 2;
        }
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
