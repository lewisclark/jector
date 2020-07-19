use super::error::Error;
use super::process::Process;
use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA, LoadLibraryExA};

// TODO: Rename to Module

pub struct Library {
    handle: HMODULE,
    is_external: bool,
}

impl Library {
    pub fn load_internal(name: &str) -> Result<Self, Error> {
        let name = match CString::new(name) {
            Ok(cstr) => Ok(cstr),
            Err(e) => Err(Error::new(format!(
                "Failed to construct CString from name arg ({})",
                e
            ))),
        }?
        .into_raw();

        let handle = unsafe { LoadLibraryA(name) };

        if handle.is_null() {
            Err(Error::new("LoadLibraryA returned NULL".to_string()))
        } else {
            Ok(Self {
                handle,
                is_external: false,
            })
        }
    }

    pub fn load_external(process: &Process, name: &str) -> Result<Self, Error> {
        let name = match CString::new(name) {
            Ok(cstr) => Ok(cstr),
            Err(e) => Err(Error::new(format!(
                "Failed to construct CString from name arg ({})",
                e
            ))),
        }?
        .into_raw();

        let handle = unsafe { LoadLibraryExA(name, 0 as HANDLE, 0) };

        if handle.is_null() {
            Err(Error::new("LoadLibraryExA returned NULL".to_string()))
        } else {
            Ok(Self {
                handle,
                is_external: true,
            })
        }
    }

    pub unsafe fn from_handle(handle: HMODULE, is_external: bool) -> Self {
        Self {
            handle,
            is_external,
        }
    }

    pub fn get_externally(process: &Process, name: &str) -> Result<Self, Error> {
        Err(Error::new("Not implemented".to_string()))
    }

    pub fn proc_address(&self, proc_name: &str) -> Result<*const (), Error> {
        match self.is_external {
            true => self.proc_address_external(proc_name),
            false => self.proc_address_internal(proc_name),
        }
    }

    fn proc_address_internal(&self, proc_name: &str) -> Result<*const (), Error> {
        let proc_name = match CString::new(proc_name) {
            Ok(cstr) => Ok(cstr),
            Err(e) => Err(Error::new(format!(
                "Failed to construct CString from proc_name arg ({})",
                e
            ))),
        }?
        .into_raw();

        let addr = unsafe { GetProcAddress(self.handle, proc_name) };

        if addr.is_null() {
            Err(Error::new("GetProcAddress returned NULL".to_string()))
        } else {
            Ok(addr as *const ())
        }
    }

    fn proc_address_external(&self, proc_name: &str) -> Result<*const (), Error> {
        Err(Error::new("Not implemented".to_string()))
    }
}
