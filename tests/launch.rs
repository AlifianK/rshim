#![cfg(windows)]

use std::{
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::WAIT_OBJECT_0,
    System::Threading::{
        CREATE_NO_WINDOW, OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
        WaitForSingleObject,
    },
};

static PROBE: OnceLock<PathBuf> = OnceLock::new();
static GUI_PROBE: OnceLock<PathBuf> = OnceLock::new();
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn probe() -> &'static Path {
    PROBE.get_or_init(|| compile_probe(false))
}

fn compile_probe(gui: bool) -> PathBuf {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("integration-fixtures");
    fs::create_dir_all(&directory).unwrap();
    let output = directory.join(format!("probe-{}-{gui}.exe", std::process::id()));
    let mut compiler = Command::new("rustc");
    if gui {
        compiler.args(["--cfg", "gui"]);
    }
    let result = compiler
        .arg("--edition=2024")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.rs"))
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

struct Fixture {
    dir: PathBuf,
    exe: PathBuf,
}

impl Fixture {
    fn new(preset: &str) -> Self {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("integration-fixtures")
            .join(format!(
                "case-{}-{} space 日本語",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("test.exe");
        fs::copy(env!("CARGO_BIN_EXE_rshim"), &exe).unwrap();
        let fixture = Self { dir, exe };
        fixture.config(&format!(
            "path = \"{}\"\nargs = {preset}\n",
            probe().display()
        ));
        fixture
    }

    fn config(&self, text: &str) {
        fs::write(self.exe.with_extension("shim"), text).unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.exe);
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }
}

fn assert_arguments(output: Output, expected: &[&OsStr]) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: String = expected
        .iter()
        .map(|arg| format!("{:04x?}\n", arg.encode_wide().collect::<Vec<_>>()))
        .collect();
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .replace("\r\n", "\n"),
        expected
    );
}

#[test]
fn quoted_presets_empty_values_and_passthrough_are_preserved() {
    let fixture =
        Fixture::new(r#"--file "C:\Program Files\app\file.txt" "" "a\"b" "C:\space dir\\""#);
    let invalid_unicode = OsString::from_wide(&[0xd800]);
    let output = fixture
        .command()
        .args([OsStr::new("hello world"), OsStr::new(""), &invalid_unicode])
        .output()
        .unwrap();
    assert_arguments(
        output,
        &[
            OsStr::new("--file"),
            OsStr::new(r"C:\Program Files\app\file.txt"),
            OsStr::new(""),
            OsStr::new("a\"b"),
            OsStr::new("C:\\space dir\\"),
            OsStr::new("hello world"),
            OsStr::new(""),
            &invalid_unicode,
        ],
    );
}

#[test]
fn raw_command_line_is_forwarded_without_requoting() {
    let fixture = Fixture::new("");
    let arguments = r#"one "" "a b" "quote\"here" "C:\space dir\\""#;
    let direct = Command::new(probe()).raw_arg(arguments).output().unwrap();
    let shimmed = fixture.command().raw_arg(arguments).output().unwrap();
    assert!(shimmed.status.success());
    assert_eq!(direct.stdout, shimmed.stdout);
}

#[test]
fn expands_environment_path_and_custom_values() {
    let fixture = Fixture::new("");
    fixture.config("path = %RSHIM_TEST_TARGET%\nargs = env RSHIM_VALUE RSHIM_REMOVE\nRSHIM_VALUE = %RSHIM_SOURCE%_suffix\nRSHIM_REMOVE =\n");
    let output = fixture
        .command()
        .env("RSHIM_TEST_TARGET", probe())
        .env("RSHIM_SOURCE", "日本語")
        .env("RSHIM_REMOVE", "old")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .replace("\r\n", "\n"),
        "Some(\"日本語_suffix\")\nNone\n"
    );
}

#[test]
fn expands_directory_placeholders_and_reads_utf8_bom() {
    let fixture = Fixture::new("");
    fixture.config(&format!(
        "\u{feff}path = \"{}\"\r\nargs = \"%~dp0\\a\" \"%~dp0\\b\"\r\n",
        probe().display()
    ));
    assert_arguments(
        fixture.command().output().unwrap(),
        &[
            fixture.dir.join("a").as_os_str(),
            fixture.dir.join("b").as_os_str(),
        ],
    );
}

#[test]
fn stdin_stdout_stderr_and_exit_code_are_forwarded() {
    let fixture = Fixture::new("stdin");
    let mut child = fixture
        .command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"stdin-ok").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"stdin-ok");
    assert_eq!(output.stderr, b"stderr-ok");
    fixture.config(&format!(
        "path = {}\nargs = exit -1073741510\n",
        probe().display()
    ));
    assert_eq!(
        fixture.command().status().unwrap().code(),
        Some(-1073741510)
    );
}

#[test]
fn batch_target_with_spaces_and_cmd_raw_arguments_work() {
    let fixture = Fixture::new("");
    let batch = fixture.dir.join("echo args.cmd");
    fs::write(&batch, "@echo off\r\necho %~1\r\nexit /b 37\r\n").unwrap();
    fixture.config(&format!(
        "path = \"{}\"\nargs = \"hello world\"\n",
        batch.display()
    ));
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(37), "{output:?}");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello world"
    );
    fixture.config("path = %SystemRoot%\\System32\\cmd.exe\n");
    let raw = r#"/d /c echo "hello" & echo second"#;
    let direct = Command::new(std::env::var_os("ComSpec").unwrap())
        .raw_arg(raw)
        .output()
        .unwrap();
    let shimmed = fixture.command().raw_arg(raw).output().unwrap();
    assert_eq!(direct.stdout, shimmed.stdout);
}

#[test]
fn invalid_or_missing_config_fails_cleanly() {
    let fixture = Fixture::new("");
    fixture.config("args = x\n");
    assert_eq!(fixture.command().output().unwrap().status.code(), Some(1));
    fixture.config("path = Z:\\nonexistent-rshim-test.exe\n");
    assert_eq!(fixture.command().output().unwrap().status.code(), Some(2));
}

#[test]
fn gui_target_preserves_redirected_streams() {
    let gui = GUI_PROBE.get_or_init(|| compile_probe(true));
    let fixture = Fixture::new("");
    fixture.config(&format!("path = {}\nargs = stdin\n", gui.display()));
    let mut child = fixture
        .command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"gui-stdin-ok")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"gui-stdin-ok");
    assert_eq!(output.stderr, b"stderr-ok");
}

#[test]
fn gui_target_returns_immediately_and_outlives_shim() {
    let gui = GUI_PROBE.get_or_init(|| compile_probe(true));
    let fixture = Fixture::new("");
    let pid_file = fixture.dir.join("gui-child.pid");
    fixture.config(&format!(
        "path = {}\nargs = sleep \"{}\"\n",
        gui.display(),
        pid_file.display()
    ));
    let started = Instant::now();
    let status = fixture
        .command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "shim waited for GUI target"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    let child_id = loop {
        if let Ok(text) = fs::read_to_string(&pid_file)
            && let Ok(id) = text.parse::<u32>()
        {
            break id;
        }
        assert!(Instant::now() < deadline, "GUI child did not start");
        thread::sleep(Duration::from_millis(20));
    };
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, child_id) };
    assert!(!handle.is_null());
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    assert_ne!(
        unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) },
        WAIT_OBJECT_0,
        "GUI child exited with the shim"
    );
    unsafe {
        TerminateProcess(handle.as_raw_handle(), 0);
    }
}

#[test]
fn installer_uses_its_own_build_and_reports_failures() {
    let fixture = Fixture::new("");
    let script = fixture.dir.join("repshims.bat");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("repshims.bat"),
        &script,
    )
    .unwrap();
    let scoop = fixture.dir.join("scoop");
    let shims = scoop.join("shims");
    fs::create_dir_all(&shims).unwrap();
    let installed = shims.join("app.exe");
    fs::write(&installed, b"old").unwrap();
    fs::write(shims.join("app.shim"), "path = unused\n").unwrap();
    fs::write(shims.join("unrelated.exe"), b"keep").unwrap();
    let run = || {
        Command::new(std::env::var_os("ComSpec").unwrap())
            .args(["/d", "/c"])
            .arg(&script)
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
            .env("SCOOP", &scoop)
            .env("SCOOP_GLOBAL", fixture.dir.join("missing-global"))
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .unwrap()
    };
    assert_eq!(run().status.code(), Some(1));
    assert_eq!(fs::read(&installed).unwrap(), b"old");
    let release = fixture.dir.join("target").join("release");
    fs::create_dir_all(&release).unwrap();
    fs::write(release.join("rshim.exe"), b"new-shim").unwrap();
    let output = run();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(fs::read(&installed).unwrap(), b"new-shim");
    assert_eq!(fs::read(shims.join("unrelated.exe")).unwrap(), b"keep");
    let original_permissions = fs::metadata(&installed).unwrap().permissions();
    let mut permissions = original_permissions.clone();
    permissions.set_readonly(true);
    fs::set_permissions(&installed, permissions).unwrap();
    let output = run();
    fs::set_permissions(&installed, original_permissions).unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
}

#[test]
fn killing_shim_terminates_its_direct_child() {
    let fixture = Fixture::new("");
    let pid_file = fixture.dir.join("child.pid");
    fixture.config(&format!(
        "path = {}\nargs = sleep \"{}\"\n",
        probe().display(),
        pid_file.display()
    ));
    let mut shim = fixture
        .command()
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let child_id = loop {
        if let Ok(text) = fs::read_to_string(&pid_file)
            && let Ok(id) = text.parse::<u32>()
        {
            break id;
        }
        if Instant::now() >= deadline {
            let _ = shim.kill();
            let _ = shim.wait();
            panic!("child did not start");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, child_id) };
    assert!(!handle.is_null());
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    shim.kill().unwrap();
    shim.wait().unwrap();
    let result = unsafe { WaitForSingleObject(handle.as_raw_handle(), 5000) };
    if result != WAIT_OBJECT_0 {
        unsafe {
            TerminateProcess(handle.as_raw_handle(), 1);
        }
    }
    assert_eq!(result, WAIT_OBJECT_0, "child survived shim termination");
}
