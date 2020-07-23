use super::error::Error;
use super::handleowner::HandleOwner;
use super::process::Process;
use super::processaccess::ProcessAccess;
use pelite::pe64::PeView;
use std::ffi::CString;
use std::mem::size_of;
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

// TODO: Rename to Module

pub struct Library {
    handle: HMODULE,
    pid_owning: u32,
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
                pid_owning: Process::from_current().pid()?,
                is_external: false,
            })
        }
    }

    pub fn load_external(_process: &Process, _name: &str) -> Result<Self, Error> {
        Err(Error::new(
            "Library::load_external not implemented".to_string(),
        ))
    }

    pub unsafe fn from_handle(handle: HMODULE, pid_owning: u32, is_external: bool) -> Self {
        Self {
            handle,
            pid_owning,
            is_external,
        }
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

    fn proc_address_external(&self, _proc_name: &str) -> Result<*const (), Error> {
        // TODO: Use more restrictive ProcessAccess permissions
        let process = Process::from_pid(self.pid_owning, ProcessAccess::PROCESS_ALL_ACCESS, false)?;

        Ok(0 as *const ())
    }

    fn info(&self) -> Result<MODULEINFO, Error> {
        let process = Process::from_pid(
            self.pid_owning,
            ProcessAccess::PROCESS_QUERY_INFORMATION | ProcessAccess::PROCESS_VM_READ,
            false,
        )?;

        let mut info = MODULEINFO {
            lpBaseOfDll: 0 as LPVOID,
            SizeOfImage: 0,
            EntryPoint: 0 as LPVOID,
        };

        let ret = unsafe {
            GetModuleInformation(
                process.handle(),
                self.handle,
                &mut info as *mut MODULEINFO,
                size_of::<MODULEINFO>() as u32,
            )
        };

        if ret != 0 {
            Ok(info)
        } else {
            Err(Error::new("GetModuleInformation returned NULL".to_string()))
        }
    }
}
