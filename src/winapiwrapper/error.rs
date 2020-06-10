use std::error;
use std::fmt;

#[derive(Debug)]
pub struct Error {
    err: String,
}

impl Error {
    pub fn new(err: String) -> Self {
        Self { err }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "winapiwrapper error: {}", self.err)
    }
}

impl error::Error for Error {}
