use super::process::{Process, ProcessAccess};
use pelite::{pe64::exports::Export, PeFile};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::mem::size_of;
use std::path::{Component, Path, PathBuf};
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::psapi::{
    self, EnumProcessModulesEx, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
};
use winapi::um::sysinfoapi::GetSystemDirectoryA;
use winapi::um::winnt::LPSTR;

bitflags! {
    pub struct ModulesFilterFlag: u32 {
        const LIST_MODULES_32BIT = psapi::LIST_MODULES_32BIT;
        const LIST_MODULES_64BIT = psapi::LIST_MODULES_64BIT;
        const LIST_MODULES_ALL = psapi::LIST_MODULES_ALL;
        const LIST_MODULES_DEFAULT = psapi::LIST_MODULES_DEFAULT;
    }
}

pub struct Module {
    handle: HMODULE,
    pid_owning: u32,
    is_external: bool,
}

impl Module {
    pub fn find_or_load_internal(name: &str) -> anyhow::Result<Self> {
        let name = CString::new(name)?.into_raw();
        let handle = unsafe { LoadLibraryA(name) };

        ensure!(!handle.is_null(), function_call_failure!("LoadLibraryA"),);

        Ok(unsafe { Self::from_handle(handle, Process::from_current().pid()?, false) })
    }

    pub fn find_or_load_external(pid: u32, path: &Path) -> anyhow::Result<Self> {
        let process =
            Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false)?;

        let path = fix_module_path(path, process.is_wow64()?)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("Expected a filename"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert"))?;

        // Return the already loaded module if it exists
        if let Some(module) = process.module_by_name(&file_name)? {
            return Ok(module);
        }

        // TODO: Manual map external libraries when stable
        match crate::injection::loadlibrary::inject_library(pid, &path) {
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

    // Takes snapshot_flags so proc_address_external can get module handles
    // For forwarded exports
    pub fn proc_address(&self, proc_name: &str) -> anyhow::Result<usize> {
        match self.is_external {
            true => self.proc_address_external(proc_name),
            false => self.proc_address_internal(proc_name),
        }
    }

    fn proc_address_internal(&self, proc_name: &str) -> anyhow::Result<usize> {
        let proc_name = CString::new(proc_name)?.into_raw();
        let addr = unsafe { GetProcAddress(self.handle, proc_name) };

        ensure!(!addr.is_null(), function_call_failure!("GetProcAddress"),);

        Ok(addr as usize)
    }

    // We load system modules from disk because we know the file location
    // And the proc offset will be the same
    fn proc_address_external(&self, proc_name: &str) -> anyhow::Result<usize> {
        let proc = Process::from_pid(
            self.pid_owning,
            ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION,
            false,
        )?;

        let path = fix_module_path(&self.path()?, proc.is_wow64()?)?;

        let dll_bytes = {
            let mut file = OpenOptions::new().read(true).open(&path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            buf
        };

        // TODO: Cache pe inside the Module struct - running it for every proc_address is expensive
        let exports_by = PeFile::from_bytes(&dll_bytes)?.exports()?.by()?;

        ensure!(
            exports_by.check_sorted()?,
            "Function exports table is not sorted"
        );

        let base_address = self.info()?.lpBaseOfDll as usize;

        match exports_by.name(proc_name)? {
            Export::Symbol(&rva) => Ok(rva as usize + base_address),
            Export::Forward(name) => {
                // TODO: Check for ordinal forwarded exports
                let name = name.to_str()?;

                let v: Vec<&str> = name.split('.').take(2).collect();
                ensure!(
                    v.len() == 2,
                    "Named forwarded export was not formatted properly"
                );

                let (dll, fwd_proc_name) =
                    (v.get(0).unwrap().to_ascii_lowercase(), v.get(1).unwrap());
                let lib = Self::find_or_load_external(self.pid_owning, Path::new(&dll))?;

                lib.proc_address_external(fwd_proc_name)
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

        ensure!(ret != 0, function_call_failure!("GetModuleInformation"),);

        Ok(info)
    }

    pub fn path(&self) -> anyhow::Result<PathBuf> {
        let proc = Process::from_pid(
            self.pid_owning,
            ProcessAccess::PROCESS_QUERY_INFORMATION | ProcessAccess::PROCESS_VM_READ,
            false,
        )?;

        let mut buf = vec![0; 0x200];
        let ret = unsafe {
            GetModuleFileNameExA(
                proc.handle(),
                self.handle,
                buf.as_mut_ptr() as LPSTR,
                buf.len() as u32,
            )
        } as usize;

        ensure!(
            ret != 0 && ret <= buf.len(),
            function_call_failure!("GetModuleFileNameExA"),
        );

        buf.resize(ret, 0);

        Ok(Path::new(&CString::new(buf)?.into_string()?.to_ascii_lowercase()).to_path_buf())
    }

    pub fn file_name(&self) -> anyhow::Result<String> {
        Ok(self
            .path()?
            .file_name()
            .ok_or_else(|| anyhow!("Failed to get file name from module path"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert OsStr path to str"))?
            .to_string())
    }
}

// Modules struct
// Iterates through the loaded modules in a process
pub struct Modules {
    modules: Vec<HMODULE>,
    pid: u32,
    is_external: bool,
}

impl Modules {
    pub fn new(
        pid: u32,
        len_needed: Option<usize>,
        filter_flag: Option<ModulesFilterFlag>,
    ) -> anyhow::Result<Self> {
        let process = Process::from_pid(
            pid,
            ProcessAccess::PROCESS_QUERY_INFORMATION | ProcessAccess::PROCESS_VM_READ,
            false,
        )?;

        let filter_flag = filter_flag.unwrap_or(match process.is_wow64()? {
            true => ModulesFilterFlag::LIST_MODULES_32BIT,
            false => ModulesFilterFlag::LIST_MODULES_ALL,
        });

        let mut buf: Vec<HMODULE> = vec![std::ptr::null_mut(); len_needed.unwrap_or(0x200)];
        let bytes_allocated = buf.len() * size_of::<HMODULE>();

        let mut bytes_needed: u32 = 0;
        let ret = unsafe {
            EnumProcessModulesEx(
                process.handle(),
                buf.as_mut_ptr() as *mut HMODULE,
                bytes_allocated as u32,
                &mut bytes_needed,
                filter_flag.bits(),
            )
        };

        ensure!(ret != 0, function_call_failure!("EnumProcessModulesEx"));

        let len_needed = bytes_needed as usize * size_of::<HMODULE>();
        if len_needed > buf.len() {
            Self::new(pid, Some(len_needed), Some(filter_flag))
        } else {
            buf.resize(len_needed, std::ptr::null_mut());
            buf.reverse();

            Ok(Self {
                modules: buf,
                pid,
                is_external: process.is_external(),
            })
        }
    }
}

impl Iterator for Modules {
    type Item = Module;

    fn next(&mut self) -> Option<Self::Item> {
        match self.modules.pop() {
            Some(module_handle) => {
                Some(unsafe { Module::from_handle(module_handle, self.pid, self.is_external) })
            }
            None => None,
        }
    }
}

// Retrieves the system directory (C:\Windows\System32)
// https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya
pub fn get_system_dir() -> anyhow::Result<PathBuf> {
    let mut buf = vec![0; 0x200];
    let ret = unsafe { GetSystemDirectoryA(buf.as_mut_ptr() as LPSTR, buf.len() as u32) } as usize;

    buf.resize(ret, 0);

    let str_dir = CString::new(buf)?.into_string()?.to_ascii_lowercase();

    Ok(Path::new(&str_dir).to_path_buf())
}

// https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
// C:\Windows\System32\* -> C:\Windows\SysWOW64\*
pub fn system_module_path_to_wow64_path(system_module_path: &Path) -> anyhow::Result<PathBuf> {
    let mut wow64_path = PathBuf::new();

    for c in system_module_path.components() {
        match c {
            Component::Normal(name) => {
                if name
                    .to_str()
                    .ok_or_else(|| anyhow!("Conversion failed"))?
                    .to_ascii_lowercase()
                    == "system32"
                {
                    wow64_path.push("syswow64");
                } else {
                    wow64_path.push(name);
                }
            }
            Component::Prefix(prefix) => {
                wow64_path.push(prefix.as_os_str());
                wow64_path.push("\\");
            }
            _ => (),
        }
    }

    Ok(wow64_path)
}

pub fn is_system_module(module_path: &Path) -> anyhow::Result<bool> {
    Ok(module_path.starts_with(get_system_dir()?))
}

// Applies transformations to the path, such as
// c runtime path correction, system path to wow64 path correction
// Input paths must be lowercase
// TODO: file name to full path - imports only contain dll file name so we need to search
// https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
fn fix_module_path(path: &Path, is_wow64_module: bool) -> anyhow::Result<PathBuf> {
    let mut path = path.to_path_buf();
    path.set_extension("dll");

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Module path did not contain a filename"))?
        .to_str()
        .ok_or_else(|| anyhow!("Failed to convert OsStr to str"))?
        .to_ascii_lowercase();

    // Steps
    // If just file name, find file and convert to full path
    // If file_name is a crt library, set path to C:\Windows\System32\downlevel\<lib>
    // If is_system_module && is_wow64_module, prepend wow64_dir to path

    if file_name.starts_with("api-ms-win-crt-") {
        path.push(get_system_dir()?);
        path.push("downlevel\\");
        path.push(file_name);
    }

    if is_wow64_module && is_system_module(&path)? {
        path = system_module_path_to_wow64_path(&path)?;
    }

    Ok(path)
}
