use super::error::Error;
use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

pub struct Library {
    handle: HMODULE,
}

impl Library {
    pub fn load(name: &str) -> Result<Self, Error> {
        let name = match CString::new(name) {
            Ok(cstr) => Ok(cstr),
            Err(e) => Err(Error::new(
                "Failed to construct CString from name arg".to_string(),
            )),
        }?
        .into_raw();

        let handle = unsafe { LoadLibraryA(name) };

        if handle.is_null() {
            Err(Error::new("LoadLibraryA returned NULL".to_string()))
        } else {
            Ok(Self { handle })
        }
    }

    pub fn proc_address(&self, proc_name: &str) -> Result<*const (), Error> {
        let proc_name = match CString::new(proc_name) {
            Ok(cstr) => Ok(cstr),
            Err(e) => Err(Error::new(
                "Failed to construct CString from proc_name arg".to_string(),
            )),
        }?
        .into_raw();

        let addr = unsafe { GetProcAddress(self.handle, proc_name) };

        if addr.is_null() {
            Err(Error::new("GetProcAddress returned NULL".to_string()))
        } else {
            Ok(addr as *const ())
        }
    }
}
