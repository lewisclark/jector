use std::env::Args;
use std::error;
use std::fmt;
use std::fs::File;

#[derive(Debug)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Config error ({})", self.0)
    }
}

impl error::Error for Error {}

#[derive(Debug)]
pub struct Config {
    cur_exe: String,
    pid: usize,
    dll_file: File,
}

impl Config {
    pub fn from_args(args: &mut Args) -> Result<Self, Box<dyn error::Error>> {
        let cur_exe = match args.next() {
            Some(path) => path,
            None => return Err(Box::new(Error("No current exe"))),
        };

        let pid: usize = match args.next() {
            Some(pid) => pid,
            None => return Err(Box::new(Error("No pid"))),
        }
        .parse()?;

        let dll_file = match args.next() {
            Some(path) => File::open(path),
            None => return Err(Box::new(Error("No dll path"))),
        }?;

        Ok(Self {
            cur_exe,
            pid,
            dll_file,
        })
    }

	pub fn cur_exe(&self) -> &str {
		&self.cur_exe
	}

	pub fn pid(&self) -> usize {
		self.pid
	}

	pub fn dll_file(&self) -> &File {
		&self.dll_file
	}

	pub fn dll_file_mut(&mut self) -> &mut File {
		&mut self.dll_file
	}
}
