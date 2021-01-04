use super::handleowner::HandleOwner;
use super::process::{Process, ProcessAccess};
use super::snapshot::SnapshotFlags;
use super::WinApiError;
use pelite::{pe64::exports::Export, PeFile};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::mem::size_of;
use std::path::{Component, Path, PathBuf};
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::psapi::{GetModuleFileNameExA, GetModuleInformation, MODULEINFO};
use winapi::um::sysinfoapi::GetSystemDirectoryA;
use winapi::um::winnt::LPSTR;
use winapi::um::wow64apiset::GetSystemWow64DirectoryA;

pub struct Module {
    handle: HMODULE,
    pid_owning: u32,
    is_external: bool,
}

impl Module {
    pub fn find_or_load_internal(name: &str) -> anyhow::Result<Self> {
        let name = CString::new(name)?.into_raw();
        let handle = unsafe { LoadLibraryA(name) };

        ensure!(
            !handle.is_null(),
            WinApiError::FunctionCallFailure("LoadLibraryA".to_string())
        );

        Ok(unsafe { Self::from_handle(handle, Process::from_current().pid()?, false) })
    }

    pub fn find_or_load_external(
        pid: u32,
        path: &Path,
        snapshot_flags: Option<SnapshotFlags>,
    ) -> anyhow::Result<Self> {
        let process =
            Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false)?;

        let path = fix_module_path(path, process.is_wow64()?)?;
        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("Expected a filename"))?
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert"))?;

        // Return the already loaded module if it exists
        if let Some(entry) = process.module_entry_by_name(&file_name, snapshot_flags)? {
            return Ok(unsafe { Self::from_handle(entry.hModule, pid, true) });
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
    pub fn proc_address(
        &self,
        proc_name: &str,
        snapshot_flags: Option<SnapshotFlags>,
    ) -> anyhow::Result<usize> {
        match self.is_external {
            true => self.proc_address_external(proc_name, snapshot_flags),
            false => self.proc_address_internal(proc_name),
        }
    }

    fn proc_address_internal(&self, proc_name: &str) -> anyhow::Result<usize> {
        let proc_name = CString::new(proc_name)?.into_raw();
        let addr = unsafe { GetProcAddress(self.handle, proc_name) };

        ensure!(
            !addr.is_null(),
            WinApiError::FunctionCallFailure("GetProcAddress".to_string())
        );

        Ok(addr as usize)
    }

    // We load system modules from disk because we know the file location
    // And the proc offset will be the same
    fn proc_address_external(
        &self,
        proc_name: &str,
        snapshot_flags: Option<SnapshotFlags>,
    ) -> anyhow::Result<usize> {
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
                let lib =
                    Self::find_or_load_external(self.pid_owning, Path::new(&dll), snapshot_flags)?;

                lib.proc_address_external(fwd_proc_name, snapshot_flags)
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
            WinApiError::FunctionCallFailure("GetModuleFileNameExA".to_string())
        );

        buf.resize(ret, 0);

        Ok(Path::new(&CString::new(buf)?.into_string()?.to_ascii_lowercase()).to_path_buf())
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

// Retrieves the WoW64 system directory
// https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-getsystemwow64directorya
pub fn get_wow64_dir() -> anyhow::Result<PathBuf> {
    let mut buf = vec![0; 0x200];
    let ret =
        unsafe { GetSystemWow64DirectoryA(buf.as_mut_ptr() as LPSTR, buf.len() as u32) } as usize;

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
