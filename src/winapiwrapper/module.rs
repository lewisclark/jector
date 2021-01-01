use super::handleowner::HandleOwner;
use super::process::{Process, ProcessAccess};
use super::WinApiError;
use std::ffi::CString;
use std::mem::size_of;
use std::path::Path;
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

#[cfg(target_arch = "x86")]
use pelite::pe32::{
    exports::Export::{Forward, Symbol},
    Pe, PeView,
};

#[cfg(target_arch = "x86_64")]
use pelite::pe64::{
    exports::Export::{Forward, Symbol},
    Pe, PeView,
};

pub struct Module {
    handle: HMODULE,
    pid_owning: u32,
    is_external: bool,
}

impl Module {
    pub fn load_internal(name: &str) -> anyhow::Result<Self> {
        let name = CString::new(name)?.into_raw();
        let handle = unsafe { LoadLibraryA(name) };

        ensure!(
            !handle.is_null(),
            WinApiError::FunctionCallFailure("LoadLibraryA".to_string())
        );

        Ok(unsafe { Self::from_handle(handle, Process::from_current().pid()?, false) })
    }

    pub fn load_external(pid: u32, name: &str) -> anyhow::Result<Self> {
        let path = Path::new(&name.to_ascii_lowercase()).with_extension("dll");
        let name = path
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert Path to str"))?;

        let process =
            Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false)?;

        // Check if the module is already loaded in the target process first
        if let Some(entry) = process.module_entry_by_name(&name)? {
            return Ok(unsafe { Self::from_handle(entry.hModule, pid, true) });
        }

        // It's not loaded, let's load it ourself

        // FIXME: Temporary path resolution
        let loc = if name.starts_with("api-ms-win-crt-") {
            "C:\\Windows\\System32\\downlevel\\a"
        } else {
            "C:\\Windows\\System32\\a"
        };

        let mut lib_path = Path::new(loc).to_path_buf();
        lib_path.set_file_name(name);
        let lib_path = lib_path
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert PathBuf to str".to_string()))?;

        // TODO: Manual map external libraries when stable
        match crate::injection::loadlibrary::inject_library(pid, lib_path) {
            Ok(base) => Ok(unsafe { Self::from_handle(base as HMODULE, pid, true) }),
            Err(e) => Err(e),
        }
    }

    pub unsafe fn from_handle(handle: HMODULE, pid_owning: u32, is_external: bool) -> Self {
        Self {
            handle,
            pid_owning,
            is_external,
        }
    }

    pub fn handle(&self) -> HMODULE {
        self.handle
    }

    pub fn proc_address(&self, proc_name: &str) -> anyhow::Result<*const ()> {
        match self.is_external {
            true => self.proc_address_external(proc_name),
            false => self.proc_address_internal(proc_name),
        }
    }

    fn proc_address_internal(&self, proc_name: &str) -> anyhow::Result<*const ()> {
        let proc_name = CString::new(proc_name)?.into_raw();
        let addr = unsafe { GetProcAddress(self.handle, proc_name) };

        ensure!(
            !addr.is_null(),
            WinApiError::FunctionCallFailure("GetProcAddress".to_string())
        );

        Ok(addr as *const ())
    }

    fn proc_address_external(&self, proc_name: &str) -> anyhow::Result<*const ()> {
        let process = Process::from_pid(self.pid_owning, ProcessAccess::PROCESS_VM_READ, false)?;
        let info = self.info()?;

        let mut buf = vec![0; info.SizeOfImage as usize];
        process.read_memory(&mut buf, info.lpBaseOfDll as usize)?;

        // TODO: Cache pe inside the Module struct - running it for every proc_address is expensive
        let pe = PeView::from_bytes(buf.as_slice())?;
        let exports_by = pe.exports()?.by()?;

        ensure!(
            exports_by.check_sorted()?,
            "Function exports table is not sorted"
        );

        match exports_by.name(proc_name)? {
            Symbol(&rva) => Ok((rva as usize + info.lpBaseOfDll as usize) as *const ()),
            Forward(name) => {
                // TODO: Check for ordinal forwarded exports
                let name = name.to_str()?;

                let v: Vec<&str> = name.split('.').take(2).collect();
                ensure!(
                    v.len() == 2,
                    "Named forwarded export was not formatted properly"
                );

                let (dll, fwd_proc_name) = (v.get(0).unwrap(), v.get(1).unwrap());
                let lib = Self::load_external(self.pid_owning, dll)?;

                lib.proc_address(fwd_proc_name)
            }
        }
    }

    pub fn info(&self) -> anyhow::Result<MODULEINFO> {
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

        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("GetModuleInformation".to_string())
        );

        Ok(info)
    }
}

// System modules are loaded at the same base address across processes (changes on reboot)
pub fn is_system_module(name: &str) -> bool {
    let name = name.to_ascii_lowercase();

    matches!(name.as_str(), "kernel32.dll" | "ntdll.dll")
}
