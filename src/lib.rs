#[macro_use]
extern crate bitflags;

use pelite::pe64::{Pe, PeFile};
use winapi::um::winnt::IMAGE_FILE_DLL;

mod error;
mod injection;
mod winapiwrapper;

use error::Error;
pub use injection::injectionmethod::InjectionMethod;

pub fn inject_pid(
    pid: u32,
    dll: &[u8],
    method: InjectionMethod,
) -> Result<(), Box<dyn std::error::Error>> {
    let pe = PeFile::from_bytes(dll)?;
    if pe.file_header().Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        return Err(Box::new(Error::new("Expected library PE file".to_string())));
    }

    injection::inject(pid, pe, dll, method)
}
