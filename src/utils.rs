use std::env::var_os;
use std::error::Error;
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::fs::{set_permissions, Permissions};
use std::io::{self, ErrorKind, Write};
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
            Self::IO(e) => e.fmt(f),
            Self::Status(o) => write!(f, "{}", &String::from_utf8_lossy(&o.stderr)),
        }
    }
}

impl Error for ExecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::IO(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ExecError {
    fn from(e: io::Error) -> Self {
        Self::IO(e)
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
    let p = path.as_ref();
    if p == Path::new("~") {
        get_homepath()
    } else {
        p.strip_prefix("~/")
            .ok()
            .and_then(|r| get_homepath().map(|h| h.join(r)))
    }
    .unwrap_or_else(|| p.to_path_buf())
}

pub trait ExpandUser {
    fn expanduser(&self) -> PathBuf;
}

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

impl IsExecutable for Path {
    fn is_executable(&self) -> bool {
        is_executable(self)
    }
}

#[cfg(unix)]
pub fn clear_permissions<P: AsRef<Path>>(path: P, perm: Permissions) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = path.as_ref().metadata()?.permissions().mode();
    set_permissions(path, Permissions::from_mode(mode & !perm.mode()))
}

#[cfg(unix)]
pub fn clear_go_permissions<P: AsRef<Path>>(path: P) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    clear_permissions(path, Permissions::from_mode(0o077))
}

pub fn time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
