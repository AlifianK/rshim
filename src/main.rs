mod shims;
use shims::Shim;

use std::{
    env,
    ffi::CString,
    mem::size_of,
    path::Path,
    process::{Command, exit},
    ptr::null_mut,
};

use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx,
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOA, ShellExecuteExA,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_NORMAL;
use windows_sys::core::BOOL;

type DWORD = std::os::raw::c_ulong;

const TRUE: BOOL = 1;
const FALSE: BOOL = 0;

unsafe extern "system" fn routine_handler(evt: DWORD) -> BOOL {
    match evt {
        CTRL_C_EVENT => TRUE,        //eprintln!("ctrl_c handled!"),
        CTRL_BREAK_EVENT => TRUE,    //eprintln!("ctrl_break handled!"),
        CTRL_CLOSE_EVENT => TRUE,    //eprintln!("ctrl_close handled!"),
        CTRL_LOGOFF_EVENT => TRUE,   //eprintln!("ctrl_logoff handled!"),
        CTRL_SHUTDOWN_EVENT => TRUE, //eprintln!("ctrl_shutdown handled!"),
        other => {
            eprintln!("unknown event number: {}, unhandled!", other);
            return FALSE;
        }
    }
}

const EXIT_FAILED_LOAD_SHIM: i32 = 1;
const EXIT_FAILED_SPAWN_PROG: i32 = 2;
const EXIT_FAILED_WAIT_PROG: i32 = 3;
const EXIT_PROG_TERMINATED: i32 = 4;

const ERROR_ELEVATION_REQUIRED: i32 = 740;
fn main() {
    let res: BOOL = unsafe { SetConsoleCtrlHandler(Some(routine_handler), TRUE) };
    if res == FALSE {
        eprintln!("shim: register Ctrl handler failed.");
    }

    let calling_args: Vec<_> = env::args().skip(1).collect();
    let shim = match Shim::init() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error while loading shim: {}", e);
            exit(EXIT_FAILED_LOAD_SHIM);
        }
    };
    let args = if let Some(mut shim_args) = shim.args {
        shim_args.extend_from_slice(calling_args.as_slice());
        shim_args
    } else {
        calling_args
    };
    let mut cmd = match Command::new(&shim.target_path).args(&args).spawn() {
        Ok(v) => v,
        Err(e) if e.raw_os_error() == Some(ERROR_ELEVATION_REQUIRED) => {
            exit(execute_elevated(&shim.target_path, &args))
        }
        Err(e) => {
            eprintln!(
                "Error while spawning target program `{}`: {}",
                shim.target_path.to_string_lossy(),
                e
            );
            exit(EXIT_FAILED_SPAWN_PROG);
        }
    };
    let status = match cmd.wait() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Error while waiting target program `{}`: {}",
                shim.target_path.to_string_lossy(),
                e
            );
            exit(EXIT_FAILED_WAIT_PROG);
        }
    };
    exit(status.code().unwrap_or(EXIT_PROG_TERMINATED))
}

fn execute_elevated(program: &Path, args: &[String]) -> i32 {
    let runas = CString::new("runas").unwrap();
    let program = CString::new(program.to_str().unwrap()).unwrap();
    let mut params = String::new();
    for arg in args.iter() {
        params.push(' ');
        if arg.len() == 0 {
            params.push_str("\"\"");
        } else if arg.find(&[' ', '\t', '"'][..]).is_none() {
            params.push_str(&arg);
        } else {
            params.push('"');
            for c in arg.chars() {
                match c {
                    '\\' => params.push_str("\\\\"),
                    '"' => params.push_str("\\\""),
                    c => params.push(c),
                }
            }
            params.push('"');
        }
    }

    let params = CString::new(&params[..]).unwrap();
    let mut info = SHELLEXECUTEINFOA::default();
    info.cbSize = size_of::<SHELLEXECUTEINFOA>() as DWORD;
    info.fMask = SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS;
    // Cast from *const i8 to *const u8
    info.lpVerb = runas.as_ptr().cast::<u8>();
    info.lpFile = program.as_ptr().cast::<u8>();
    info.lpParameters = params.as_ptr().cast::<u8>();
    info.nShow = SW_NORMAL;
    let res = unsafe {
        CoInitializeEx(
            null_mut(),
            COINIT_APARTMENTTHREADED as u32 | COINIT_DISABLE_OLE1DDE as u32,
        );
        ShellExecuteExA(&mut info as *mut _)
    };
    if res == FALSE || info.hProcess == null_mut() {
        return EXIT_FAILED_SPAWN_PROG;
    }
    let mut code: DWORD = 0;
    unsafe {
        WaitForSingleObject(info.hProcess, INFINITE);
        if GetExitCodeProcess(info.hProcess, &mut code as *mut _) == FALSE {
            return EXIT_FAILED_WAIT_PROG;
        }
    }
    return code as i32;
}
