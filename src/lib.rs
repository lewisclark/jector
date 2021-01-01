#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate anyhow;

#[macro_use]
extern crate thiserror;

#[cfg(target_arch = "x86")]
use pelite::pe32::{Pe, PeFile};

#[cfg(target_arch = "x86_64")]
use pelite::pe64::{Pe, PeFile};

use winapi::um::winnt::IMAGE_FILE_DLL;

mod injection;
mod winapiwrapper;

pub use injection::injectionmethod::InjectionMethod;
use winapiwrapper::window::Window;

pub fn inject_pid(pid: u32, dll: &[u8], method: InjectionMethod) -> anyhow::Result<usize> {
    let pe = PeFile::from_bytes(dll)?;
    ensure!(pe.file_header().Characteristics & IMAGE_FILE_DLL != 0);

    Ok(injection::inject(pid, pe, dll, method)?)
}

pub fn inject_window(
    window_name: &str,
    dll: &[u8],
    method: InjectionMethod,
) -> anyhow::Result<usize> {
    let window = Window::find(window_name)?;

    if let Some(window) = window {
        inject_pid(window.pid(), dll, method)
    } else {
        bail!("Failed to find window with name '{}'", window_name)
    }
}
