#[macro_use]
extern crate bitflags;

#[macro_use]
extern crate anyhow;

#[macro_use]
extern crate thiserror;

use pelite::{PeFile, Wrap};
use winapi::um::winnt::IMAGE_FILE_DLL;

mod injection;
mod winapiwrapper;

pub use injection::injectionmethod::InjectionMethod;
use winapiwrapper::process::{Process, ProcessAccess, Processes};
use winapiwrapper::window::Window;

pub fn inject_pid(pid: u32, dll: &[u8], method: InjectionMethod) -> anyhow::Result<usize> {
    let pe = PeFile::from_bytes(dll)?;
    ensure!(pe.file_header().Characteristics & IMAGE_FILE_DLL != 0);

    // If the library is 32-bit, ensure the target process is running under WOW64
    if matches!(pe, Wrap::T32(_pe32)) {
        let process =
            Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false)?;
        ensure!(
            process.is_wow64()?,
            "Library is 32-bit but process is not running under WOW64"
        );
    }

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

pub fn inject_process_name(
    process_name: &str,
    dll: &[u8],
    method: InjectionMethod,
) -> anyhow::Result<usize> {
    let process_name = process_name.to_ascii_lowercase();
    let processes = Processes::new(None)?;

    for pid in processes {
        let proc =
            match Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false) {
                Ok(proc) => proc,
                Err(_e) => continue, // It might be a system process which we can't open a handle for
            };

        let file_name = proc
            .path()?
            .file_name()
            .ok_or_else(|| anyhow!("No file name for path"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert OsStr to str"))?
            .to_ascii_lowercase();

        if file_name == process_name {
            return inject_pid(pid, dll, method);
        }
    }

    Err(anyhow!(
        "Failed to find process with name: '{}'",
        process_name
    ))
}
