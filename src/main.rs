#[macro_use]
extern crate bitflags;

use pelite::pe64::{PeFile, Pe};
use winapi::um::winnt::IMAGE_FILE_DLL;
use std::env;
use std::error;
use std::fmt;
use std::io::Read;

mod config;
mod injector;
mod winapiwrapper;

use config::Config;
use injector::injector::Injector;
use injector::manualmap::ManualMapInjector;

#[derive(Debug)]
struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Image file parsing error: {}", self.0)
    }
}

impl error::Error for Error {}

fn main() -> Result<(), Box<dyn error::Error>> {
    let mut args = env::args();
    println!("args: {:?}", args);

    let mut config = Config::from_args(&mut args)?;
    println!("config: {:?}", config);

    let mut file_bytes = Vec::new();
    config.dll_file_mut().read_to_end(&mut file_bytes)?;

    let pe = PeFile::from_bytes(file_bytes.as_slice())?;

    if pe.file_header().Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        return Err(Box::new(Error("Expected library PE file".to_string())));
    }

    ManualMapInjector::inject(config.pid(), pe, &file_bytes)?;

    Ok(())
}
