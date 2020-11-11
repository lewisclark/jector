#[macro_use]
extern crate bitflags;

use pelite::pe64::{Pe, PeFile};
use winapi::um::winnt::IMAGE_FILE_DLL;

mod error;
mod injection;
mod winapiwrapper;

use error::Error;
pub use injection::injectionmethod::InjectionMethod;
use winapiwrapper::window::Window;

pub fn inject_pid(
    pid: u32,
    dll: &[u8],
    method: InjectionMethod,
) -> Result<usize, Box<dyn std::error::Error>> {
    let pe = PeFile::from_bytes(dll)?;
    if pe.file_header().Characteristics & IMAGE_FILE_DLL != IMAGE_FILE_DLL {
        return Err(Box::new(Error::new("Expected library PE file".to_string())));
    }

    injection::inject(pid, pe, dll, method)
}

pub fn inject_window(
    window_name: &str,
    dll: &[u8],
    method: InjectionMethod,
) -> Result<usize, Box<dyn std::error::Error>> {
    let window = Window::find(window_name);

    if let Some(window) = window {
        inject_pid(window.pid(), dll, method)
    } else {
        Err(Box::new(Error::new(format!(
            "Failed to find window with name '{}'",
            window_name
        ))))
    }
}
