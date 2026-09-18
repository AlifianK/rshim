use std::{
    env,
    ffi::OsString,
    fs,
    io::{self, Error, ErrorKind},
    path::{Path, PathBuf},
};

pub struct Shim {
    pub target_path: PathBuf,
    // Preset arguments are Windows command-line text, not whitespace-delimited tokens.
    pub args: OsString,
    pub env: Vec<(String, OsString)>,
}

impl Shim {
    pub fn init() -> io::Result<Self> {
        let mut shim_path = env::current_exe()?;
        shim_path.set_extension("shim");
        let content = fs::read_to_string(&shim_path).map_err(|error| {
            Error::new(
                error.kind(),
                format!("reading {}: {error}", shim_path.display()),
            )
        })?;
        Self::parse(&content, &shim_path, |name| env::var_os(name))
    }

    fn parse(
        content: &str,
        shim_path: &Path,
        lookup: impl Fn(&str) -> Option<OsString>,
    ) -> io::Result<Self> {
        if content.contains('\0') {
            return Err(Error::new(ErrorKind::InvalidData, "NUL in shim file"));
        }
        let mut target_path = None;
        let mut args = OsString::new();
        let mut env = Vec::new();
        for line in content.strip_prefix('\u{feff}').unwrap_or(content).lines() {
            let line = line.trim_start();
            if line.is_empty() || line.starts_with(['#', ';']) {
                continue;
            }
            let (name, value) = line.split_once('=').ok_or_else(|| {
                Error::new(ErrorKind::InvalidData, format!("invalid shim line: {line}"))
            })?;
            let name = name.trim();
            let value = value.trim_start_matches([' ', '\t']);
            match name {
                "path" => {
                    let value = value.trim();
                    let value = value
                        .strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .unwrap_or(value);
                    if value.is_empty() || value.contains('"') {
                        return Err(Error::new(ErrorKind::InvalidData, "invalid target path"));
                    }
                    target_path = Some(PathBuf::from(expand_env(value, &lookup)));
                }
                "args" => {
                    args.clear();
                    let mut parts = value.split("%~dp0");
                    args.push(parts.next().unwrap_or_default());
                    for part in parts {
                        args.push(shim_path.parent().unwrap_or(Path::new("")));
                        args.push(part);
                    }
                }
                "" => return Err(Error::new(ErrorKind::InvalidData, "empty environment name")),
                _ => env.push((name.to_owned(), expand_env(value, &lookup))),
            }
        }
        let target_path = target_path.ok_or_else(|| {
            Error::new(
                ErrorKind::InvalidData,
                format!("no path key in {}", shim_path.display()),
            )
        })?;
        if target_path.as_os_str().is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "empty expanded target path",
            ));
        }
        Ok(Self {
            target_path,
            args,
            env,
        })
    }
}

// Expand against the inherited environment. Unknown names remain literal;
// percent signs introduced by replacements are not recursively expanded.
fn expand_env(mut input: &str, lookup: &impl Fn(&str) -> Option<OsString>) -> OsString {
    let mut result = OsString::new();
    while let Some(start) = input.find('%') {
        result.push(&input[..start]);
        input = &input[start..];
        let Some(end) = input[1..].find('%').map(|pos| pos + 1) else {
            break;
        };
        let name = &input[1..end];
        if let Some(value) = (!name.is_empty()).then(|| lookup(name)).flatten() {
            result.push(value);
        } else {
            result.push(&input[..=end]);
        }
        input = &input[end + 1..];
    }
    result.push(input);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_command_line_and_environment_quotes() {
        let shim = Shim::parse(
            "\u{feff}path = \"C:\\Program Files\\app.exe\"\r\nargs = --file \"a b\" \"\"\r\nVAR = \"literal\"",
            Path::new(r"C:\shims\app.shim"), |_| None,
        ).unwrap();
        assert_eq!(shim.target_path, Path::new(r"C:\Program Files\app.exe"));
        assert_eq!(shim.args, "--file \"a b\" \"\"");
        assert_eq!(shim.env, vec![("VAR".into(), "\"literal\"".into())]);
    }

    #[test]
    fn expands_path_environment_and_all_directory_placeholders() {
        let shim = Shim::parse(
            "path = %ROOT%\\app.exe\nargs = \"%~dp0\\a\" %~dp0\\b\nVAR = %ROOT%;%UNKNOWN%;%%;%",
            Path::new(r"C:\shims\app.shim"),
            |name| (name == "ROOT").then(|| OsString::from(r"C:\apps")),
        )
        .unwrap();
        assert_eq!(shim.target_path, Path::new(r"C:\apps\app.exe"));
        assert_eq!(shim.args, r#""C:\shims\a" C:\shims\b"#);
        assert_eq!(shim.env[0].1, r"C:\apps;%UNKNOWN%;%%;%");
    }

    #[test]
    fn rejects_invalid_configuration() {
        for content in [
            "args = x",
            "path =",
            "path = \"\"",
            "path = a\0b",
            "path = \"a",
            "path = a\n = b",
        ] {
            assert!(
                Shim::parse(content, Path::new("a.shim"), |_| None).is_err(),
                "{content:?}"
            );
        }
    }
}
