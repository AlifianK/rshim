use crate::shims::Shim;
use std::{
    env,
    ffi::{OsStr, OsString, c_void},
    fs::File,
    io::{self, Error, Read, Seek, SeekFrom},
    mem::{size_of, transmute},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr::{null, null_mut},
};
use windows_sys::{
    Win32::{
        Foundation::{ERROR_ELEVATION_REQUIRED, WAIT_OBJECT_0},
        Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, SearchPathW,
        },
        System::{
            Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE},
            Console::{FreeConsole, GetConsoleMode, SetConsoleCtrlHandler},
            Environment::{GetCommandLineW, SetEnvironmentVariableW},
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JobObjectExtendedLimitInformation, SetInformationJobObject,
            },
            LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
            Threading::{
                CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess, GetStartupInfoW, INFINITE,
                PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
                TerminateProcess, WaitForSingleObject,
            },
        },
        UI::{
            Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
            WindowsAndMessaging::SW_NORMAL,
        },
    },
    core::{BOOL, HRESULT, PCSTR, PCWSTR, s, w},
};

const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;

pub enum Launch {
    Foreground(Process),
    Detached,
}

pub struct Process {
    handle: OwnedHandle,
    _job: OwnedHandle,
}

impl Process {
    pub fn wait(&self) -> io::Result<u32> {
        let mut code = 0;
        // The process handle stays owned and open throughout both calls.
        unsafe {
            if WaitForSingleObject(self.handle.as_raw_handle(), INFINITE) != WAIT_OBJECT_0 {
                return Err(Error::last_os_error());
            }
            if GetExitCodeProcess(self.handle.as_raw_handle(), &mut code) == 0 {
                return Err(Error::last_os_error());
            }
        }
        Ok(code)
    }
}

unsafe extern "system" fn ignore_console_event(_: u32) -> i32 {
    // Children receive console events themselves. Wait for them to finish.
    1
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in Windows string",
        ));
    }
    value.push(0);
    Ok(value)
}

// argv[0] has special Windows parsing rules: quotes group whitespace, and
// backslashes are literal. Leave the remaining UTF-16 command line untouched.
fn argument_tail(command: &[u16]) -> &[u16] {
    let mut quoted = false;
    for (index, &unit) in command.iter().enumerate() {
        match unit {
            34 => quoted = !quoted,
            9 | 32 if !quoted => return &command[index..],
            _ => {}
        }
    }
    &[]
}

fn parameters(preset: &OsStr) -> io::Result<Vec<u16>> {
    // GetCommandLineW returns process-owned, NUL-terminated storage valid for
    // the process's lifetime. Copy the tail before calling any launch API.
    let tail = unsafe {
        let ptr = GetCommandLineW();
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        argument_tail(std::slice::from_raw_parts(ptr, len))
    };
    let mut params = wide(preset)?;
    params.pop();
    params.extend_from_slice(tail);
    params.push(0);
    Ok(params)
}

fn create_job() -> io::Result<OwnedHandle> {
    unsafe {
        let raw = CreateJobObjectW(null(), null());
        if raw.is_null() {
            return Err(Error::last_os_error());
        }
        // Successful CreateJobObjectW transfers ownership of this handle to us.
        let job = OwnedHandle::from_raw_handle(raw);
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // Own the direct child. Its descendants may outlive it, which permits
        // launchers to start background applications without killing them on exit.
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        if SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        ) == 0
        {
            return Err(Error::last_os_error());
        }
        Ok(job)
    }
}

fn search_executable(target: &[u16]) -> io::Result<Vec<u16>> {
    let mut path = vec![0; 260];
    loop {
        let len = unsafe {
            SearchPathW(
                null(),
                target.as_ptr(),
                w!(".exe"),
                path.len() as u32,
                path.as_mut_ptr(),
                null_mut(),
            )
        } as usize;
        if len == 0 {
            return Err(Error::last_os_error());
        }
        if len < path.len() {
            path.truncate(len + 1);
            return Ok(path);
        }
        path.resize(len + 1, 0);
    }
}

// Read the PE header directly. The shell's executable-type query would load
// shell32 and its dependencies on every shim start.
fn subsystem(file: &mut File) -> io::Result<u16> {
    let mut dos = [0; 64];
    file.read_exact(&mut dos)?;
    if !dos.starts_with(b"MZ") {
        return Err(Error::from(io::ErrorKind::InvalidData));
    }
    let offset = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]);
    // Subsystem follows the signature, the 20-byte file header, and 68 bytes
    // of the optional header in both PE32 and PE32+ images.
    let mut nt = [0; 94];
    file.seek(SeekFrom::Start(offset.into()))?;
    file.read_exact(&mut nt)?;
    if !nt.starts_with(b"PE\0\0") {
        return Err(Error::from(io::ErrorKind::InvalidData));
    }
    Ok(u16::from_le_bytes([nt[92], nt[93]]))
}

fn file_id(file: &File) -> io::Result<(u32, u32, u32)> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(Error::last_os_error());
    }
    Ok((
        info.dwVolumeSerialNumber,
        info.nFileIndexHigh,
        info.nFileIndexLow,
    ))
}

// A bare name can resolve to this shim through its own directory or PATH, and
// launching it would start the shim again without end.
fn is_current_exe(target: &File) -> bool {
    let shim = env::current_exe().and_then(File::open);
    match (file_id(target), shim.and_then(|shim| file_id(&shim))) {
        (Ok(target), Ok(shim)) => target == shim,
        _ => false,
    }
}

pub fn launch(shim: &Shim) -> io::Result<Launch> {
    let params = parameters(&shim.args)?;
    let target = wide(shim.target_path.as_os_str())?;
    if target.contains(&34) {
        return Err(Error::new(
            io::ErrorKind::InvalidInput,
            "quote in expanded target path",
        ));
    }
    // Expand all entries against the inherited environment before applying any.
    // SetEnvironmentVariableW is thread-safe on Windows. Empty values remove a variable.
    for (name, value) in &shim.env {
        let name = wide(OsStr::new(name))?;
        let value = wide(value)?;
        if unsafe {
            SetEnvironmentVariableW(
                name.as_ptr(),
                if value.len() == 1 {
                    null()
                } else {
                    value.as_ptr()
                },
            )
        } == 0
        {
            return Err(Error::last_os_error());
        }
    }
    let batch = shim
        .target_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("cmd") || ext.eq_ignore_ascii_case("bat"));
    // Resolve after applying shim environment entries, including PATH. Use the
    // same executable for subsystem detection, process creation, and elevation.
    let resolved = if !batch && !shim.target_path.is_absolute() {
        search_executable(&target)?
    } else {
        target.clone()
    };
    // Treat an unreadable target as a console program, so that process
    // creation reports the actual error.
    let is_gui = match File::open(OsString::from_wide(&resolved[..resolved.len() - 1])) {
        Ok(file) if is_current_exe(&file) => {
            return Err(Error::new(
                io::ErrorKind::InvalidInput,
                "target path resolves to the shim itself",
            ));
        }
        Ok(mut file) => subsystem(&mut file).ok() == Some(IMAGE_SUBSYSTEM_WINDOWS_GUI),
        Err(_) => false,
    };
    let mut startup = STARTUPINFOW::default();
    unsafe {
        GetStartupInfoW(&mut startup);
    }
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    let job = if is_gui { None } else { Some(create_job()?) };
    if is_gui {
        // Redirection handles remain valid after detaching. Clear only actual
        // console handles so GUI tools can still use piped input and output.
        for handle in [
            &mut startup.hStdInput,
            &mut startup.hStdOutput,
            &mut startup.hStdError,
        ] {
            let mut mode = 0;
            if unsafe { GetConsoleMode(*handle, &mut mode) } != 0 {
                *handle = null_mut();
            }
        }
        unsafe {
            FreeConsole();
        }
        if startup.hStdInput.is_null()
            && startup.hStdOutput.is_null()
            && startup.hStdError.is_null()
        {
            startup.dwFlags &= !STARTF_USESTDHANDLES;
        }
    } else if unsafe { SetConsoleCtrlHandler(Some(ignore_console_event), 1) } == 0 {
        eprintln!(
            "shim: register Ctrl handler failed: {}",
            Error::last_os_error()
        );
    }

    let mut command = Vec::new();
    // Keep batch-file support. cmd /s /c removes the outermost quote pair
    // and interprets the original argument text using its own parsing rules.
    if batch {
        let interpreter = std::env::var_os("ComSpec").unwrap_or_else(|| "cmd.exe".into());
        let interpreter = wide(&interpreter)?;
        if interpreter.contains(&34) {
            return Err(Error::new(io::ErrorKind::InvalidInput, "quote in ComSpec"));
        }
        command.push(34);
        command.extend_from_slice(&interpreter[..interpreter.len() - 1]);
        command.extend("\" /d /s /c \"".encode_utf16());
    }
    command.push(34);
    command.extend_from_slice(&target[..target.len() - 1]);
    command.extend([34, 32]);
    command.extend_from_slice(&params[..params.len() - 1]);
    if batch {
        command.push(34);
    }
    command.push(0);
    let mut info = PROCESS_INFORMATION::default();
    // Keep the original argv[0], but launch the exact executable inspected above.
    // An explicit application path also avoids the executable-token MAX_PATH limit.
    let application = if !batch { resolved.as_ptr() } else { null() };
    let created = unsafe {
        CreateProcessW(
            application,
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup,
            &mut info,
        )
    };
    if created == 0 {
        let error = Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_ELEVATION_REQUIRED as i32) {
            return Err(error);
        }
        let handle = elevate(&resolved, &params)?;
        if is_gui {
            return Ok(Launch::Detached);
        }
        let job = job.expect("console launches create a job");
        // UAC launches through the shell; it cannot start suspended here, and
        // Windows may deny job assignment across integrity levels.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), handle.as_raw_handle()) } == 0 {
            eprintln!(
                "shim: elevated process could not join cleanup job: {}",
                Error::last_os_error()
            );
        }
        return Ok(Launch::Foreground(Process { handle, _job: job }));
    }
    // CreateProcessW succeeded and gave us ownership of both handles.
    let handle = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    if is_gui {
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            let error = Error::last_os_error();
            // GUI children have no cleanup job; closing handles cannot kill them.
            unsafe {
                TerminateProcess(handle.as_raw_handle(), 2);
            }
            return Err(error);
        }
        return Ok(Launch::Detached);
    }
    let job = job.expect("console launches create a job");
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), handle.as_raw_handle()) } == 0 {
        let error = Error::last_os_error();
        // An unassigned suspended process would otherwise remain forever.
        unsafe {
            TerminateProcess(handle.as_raw_handle(), 2);
        }
        return Err(error);
    }
    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        return Err(Error::last_os_error()); // Closing the job terminates the child.
    }
    Ok(Launch::Foreground(Process { handle, _job: job }))
}

type Export = unsafe extern "system" fn() -> isize;

fn system_function(library: PCWSTR, name: PCSTR) -> io::Result<Export> {
    unsafe {
        let module = LoadLibraryExW(library, null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32);
        if module.is_null() {
            return Err(Error::last_os_error());
        }
        GetProcAddress(module, name).ok_or_else(Error::last_os_error)
    }
}

fn elevate(target: &[u16], params: &[u16]) -> io::Result<OwnedHandle> {
    type ShellExecuteExW = unsafe extern "system" fn(*mut SHELLEXECUTEINFOW) -> BOOL;
    type CoInitializeEx = unsafe extern "system" fn(*const c_void, u32) -> HRESULT;
    type CoUninitialize = unsafe extern "system" fn();
    // Only UAC launches need the shell and COM. Load them here, not as imports,
    // so that ordinary launches do not pay their startup cost.
    let shell_execute = system_function(w!("shell32.dll"), s!("ShellExecuteExW"))?;
    let initialize = system_function(w!("ole32.dll"), s!("CoInitializeEx"))?;
    let uninitialize = system_function(w!("ole32.dll"), s!("CoUninitialize"))?;
    // Each export has the signature that the Windows SDK declares for it.
    let (shell_execute, initialize, uninitialize) = unsafe {
        (
            transmute::<Export, ShellExecuteExW>(shell_execute),
            transmute::<Export, CoInitializeEx>(initialize),
            transmute::<Export, CoUninitialize>(uninitialize),
        )
    };
    let verb: Vec<_> = "runas\0".encode_utf16().collect();
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: target.as_ptr(),
        lpParameters: params.as_ptr(),
        nShow: SW_NORMAL,
        ..Default::default()
    };
    unsafe {
        let initialized = initialize(
            null(),
            COINIT_APARTMENTTHREADED as u32 | COINIT_DISABLE_OLE1DDE as u32,
        ) >= 0;
        let success = shell_execute(&mut info);
        let error = Error::last_os_error();
        if initialized {
            uninitialize();
        }
        if success == 0 {
            return Err(error);
        }
        if info.hProcess.is_null() {
            return Err(Error::other("elevation returned no process handle"));
        }
        Ok(OwnedHandle::from_raw_handle(info.hProcess))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_only_the_executable_token() {
        for (command, expected) in [
            (
                r#""C:\Program Files\shim.exe" --file "a b" """#,
                r#" --file "a b" """#,
            ),
            ("shim.exe\tfoo  bar", "\tfoo  bar"),
            (r#"C:\"Program Files"\shim.exe arg"#, " arg"),
            ("shim.exe", ""),
        ] {
            let command: Vec<_> = command.encode_utf16().collect();
            assert_eq!(
                argument_tail(&command),
                expected.encode_utf16().collect::<Vec<_>>()
            );
        }
    }
}
