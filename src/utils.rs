use std::env::var_os;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{self, BufRead, BufReader, ErrorKind, Lines, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

#[derive(Debug)]
pub enum ExecError {
    IO(io::Error),
    Status(Output),
}

impl Display for ExecError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(err) => err.fmt(f),
            Self::Status(output) => write!(f, "{}", &String::from_utf8_lossy(&output.stderr)),
        }
    }
}

impl Error for ExecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ExecError {
    fn from(err: io::Error) -> Self {
        Self::IO(err)
    }
}

pub type ExecResult<T> = Result<T, ExecError>;

pub fn exec<S1, I, S2>(program: S1, args: I) -> ExecResult<Output>
where
    S1: AsRef<OsStr>,
    I: IntoIterator<Item = S2>,
    S2: AsRef<OsStr>,
{
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(ExecError::Status(output));
    }
    Ok(output)
}

#[cfg(unix)]
pub fn exec_stdin<S1, I, S2, S3>(program: S1, args: I, input: S3) -> ExecResult<Output>
where
    S1: AsRef<OsStr>,
    I: IntoIterator<Item = S2>,
    S2: AsRef<OsStr>,
    S3: AsRef<OsStr>,
{
    use std::os::unix::ffi::OsStrExt;

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(input.as_ref().as_bytes())?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            return Err(ExecError::Status(output));
        }
        Ok(output)
    } else {
        child.kill()?;
        Err(ExecError::IO(io::Error::new(
            ErrorKind::Other,
            "Failed to open stdin",
        )))
    }
}

#[cfg(unix)]
pub fn get_homepath() -> Option<PathBuf> {
    var_os("HOME").map(PathBuf::from)
}

#[cfg(unix)]
pub fn expanduser<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    if path == Path::new("~") {
        get_homepath()
    } else {
        path.strip_prefix("~/")
            .ok()
            .and_then(|p| get_homepath().map(|hp| hp.join(p)))
    }
    .unwrap_or_else(|| path.to_path_buf())
}

pub trait ExpandUser {
    fn expanduser(&self) -> PathBuf;
}

#[cfg(unix)]
impl ExpandUser for Path {
    fn expanduser(&self) -> PathBuf {
        expanduser(self)
    }
}

#[cfg(unix)]
pub fn is_executable<P: AsRef<Path>>(path: P) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.as_ref()
        .metadata()
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

pub trait IsExecutable {
    fn is_executable(&self) -> bool;
}

#[cfg(unix)]
impl IsExecutable for Path {
    fn is_executable(&self) -> bool {
        is_executable(self)
    }
}

#[cfg(unix)]
pub fn is_hidden<P: AsRef<Path>>(path: P) -> bool {
    use std::os::unix::ffi::OsStrExt;

    path.as_ref()
        .file_name()
        .map_or(false, |s| s.as_bytes().starts_with(b"."))
}

pub trait IsHidden {
    fn is_hidden(&self) -> bool;
}

#[cfg(unix)]
impl IsHidden for Path {
    fn is_hidden(&self) -> bool {
        is_hidden(self)
    }
}

pub fn time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn read_lines<P: AsRef<Path>>(path: P) -> io::Result<Lines<BufReader<File>>> {
    Ok(BufReader::new(File::open(path)?).lines())
}
