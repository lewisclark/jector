#[macro_use]
extern crate bitflags;

use pelite::pe64::{Pe, PeFile};
use winapi::um::winnt::IMAGE_FILE_DLL;

mod error;
mod injector;
mod winapiwrapper;

use error::Error;
use injector::manualmap;

pub fn inject_pid(pid: u32, dll: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let pe = PeFile::from_bytes(dll)?;
    if pe.file_header().Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        return Err(Box::new(Error::new("Expected library PE file".to_string())));
    }

    manualmap::inject(pid, pe, dll)
}
