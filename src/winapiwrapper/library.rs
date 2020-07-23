use super::error::Error;
use super::handleowner::HandleOwner;
use super::process::Process;
use super::processaccess::ProcessAccess;
use pelite::pe64::exports::Export::{Forward, Symbol};
use pelite::pe64::Pe;
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

    // NOTE: This must check if the library in question is already loaded
    // TODO: Manual map external libraries when stable
    pub fn load_external(pid: u32, _name: &str) -> Result<Self, Error> {
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

    fn proc_address_external(&self, proc_name: &str) -> Result<*const (), Error> {
        let process = Process::from_pid(self.pid_owning, ProcessAccess::PROCESS_VM_READ, false)?;
        let info = self.info()?;

        let mut buf: Vec<u8> = Vec::new();
        buf.resize(info.SizeOfImage as usize, 0);
        process.read_memory(buf.as_mut_slice(), info.lpBaseOfDll as usize)?;

        // TODO: Cache pe inside the Library struct - running it for every proc_address is expensive
        let pe = match PeView::from_bytes(buf.as_slice()) {
            Ok(pe) => Ok(pe),
            Err(e) => Err(Error::new(format!("PeView::from_bytes failed: {}", e))),
        }?;

        let exports = match pe.exports() {
            Ok(exports) => Ok(exports),
            Err(e) => Err(Error::new(format!(
                "Failed to obtain exports from PE: {}",
                e
            ))),
        }?;

        let by = match exports.by() {
            Ok(by) => Ok(by),
            Err(e) => Err(Error::new(format!("Failed to obtain by: {}", e))),
        }?;

        match by.check_sorted() {
            Ok(is_sorted) => {
                if !is_sorted {
                    Err(Error::new("Export table isn't sorted".to_string()))
                } else {
                    Ok(())
                }
            }
            Err(e) => Err(Error::new(format!(
                "Failed to obtain sorted status of export table: {}",
                e
            ))),
        }?;

        let export = match by.name(proc_name) {
            Ok(export) => Ok(export),
            Err(e) => Err(Error::new(format!(
                "Failed to obtain export by name: {}",
                e
            ))),
        }?;

        match export {
            Symbol(&rva) => Ok((rva as usize + info.lpBaseOfDll as usize) as *const ()),
            Forward(name) => {
                // TODO: Check for ordinal forwarded exports
                match name.to_str() {
                    Ok(name) => {
                        let v: Vec<&str> = name.split('.').take(2).collect();

                        if v.len() == 2 {
                            let (dll, fwd_proc_name) = (v.get(0).unwrap(), v.get(1).unwrap());

                            let lib = match Self::load_external(self.pid_owning, dll) {
                                Ok(lib) => Ok(lib),
                                Err(e) => Err(Error::new(format!(
                                    "Failed to load external library: {}",
                                    e
                                ))),
                            }?;

                            match lib.proc_address(fwd_proc_name) {
                                Ok(proc) => Ok(proc),
                                Err(e) => Err(Error::new(format!(
                                    "Failed to obtain proc address of forwarded export: {}",
                                    e
                                ))),
                            }
                        } else {
                            Err(Error::new(
                                "Export forward was not formatted properly".to_string(),
                            ))
                        }
                    }
                    Err(e) => Err(Error::new(format!("Failed to convert CStr to str: {}", e))),
                }
            }
        }
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
