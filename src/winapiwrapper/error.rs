use std::error;
use std::fmt;
use winapi::um::errhandlingapi::GetLastError;

fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

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
        write!(f, "{}, last error: {}", self.err, get_last_error())
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl error::Error for Error {}
