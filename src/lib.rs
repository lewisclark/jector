#[macro_use]
extern crate bitflags;

use pelite::pe64::{PeFile, Pe};
use winapi::um::winnt::IMAGE_FILE_DLL;

mod injector;
mod winapiwrapper;
mod error;

use injector::manualmap;
use error::Error;

pub fn inject_pid(pid: u32, dll: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pe = PeFile::from_bytes(dll)?;
    if pe.file_header().Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        return Err(Box::new(Error("Expected library PE file".to_string())));
    }

    manualmap::inject(pid, pe, dll)
}
