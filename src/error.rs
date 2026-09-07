use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

/// An error with the operation that produced it attached.
///
/// Runtime failures surface to the caller as text on stderr and an exit code,
/// so the context string is the whole diagnostic. The errno is kept apart from
/// it because phase 4 has to map specific failures onto the exit codes the OCI
/// caller expects.
#[derive(Debug)]
pub struct Error {
    context: String,
    errno: Option<rustix::io::Errno>,
}

impl Error {
    pub fn msg(context: impl Into<String>) -> Self {
        Self { context: context.into(), errno: None }
    }

    pub fn from_errno(context: impl Into<String>, errno: rustix::io::Errno) -> Self {
        Self { context: context.into(), errno: Some(errno) }
    }

    /// The underlying failure, where there was one. Netlink callers use it to
    /// tolerate an EEXIST that means the desired state already holds.
    pub fn errno(&self) -> Option<rustix::io::Errno> {
        self.errno
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.errno {
            Some(e) => write!(f, "{}: {}", self.context, e),
            None => f.write_str(&self.context),
        }
    }
}

impl std::error::Error for Error {}

/// Attach a description of what was being attempted to a syscall failure.
pub trait Context<T> {
    fn context(self, f: impl FnOnce() -> String) -> Result<T>;
}

impl<T> Context<T> for std::result::Result<T, rustix::io::Errno> {
    fn context(self, f: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error { context: f(), errno: Some(e) })
    }
}

impl<T> Context<T> for std::result::Result<T, std::io::Error> {
    fn context(self, f: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|e| Error {
            context: f(),
            errno: rustix::io::Errno::from_io_error(&e),
        })
    }
}
