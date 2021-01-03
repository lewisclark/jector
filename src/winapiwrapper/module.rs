use super::handleowner::HandleOwner;
use super::process::{Process, ProcessAccess};
use super::snapshot::SnapshotFlags;
use super::WinApiError;
use pelite::{pe32, pe64, pe64::exports::Export, PeFile, Wrap};
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::Read;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use winapi::shared::minwindef::{HMODULE, LPVOID};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::psapi::{GetModuleFileNameExA, GetModuleInformation, MODULEINFO};
use winapi::um::winnt::LPSTR;
use winapi::um::wow64apiset::GetSystemWow64DirectoryA;

// TODO
const SYSTEM_MODULES: &[&str] = &[
    "windows\\system32\\kernel32.dll",
    "windows\\system32\\vcruntime140.dll",
];

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
        name: &str,
        snapshot_flags: Option<SnapshotFlags>,
    ) -> anyhow::Result<Self> {
        let path = Path::new(&name.to_ascii_lowercase()).with_extension("dll");
        let name = path
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert Path to str"))?;

        let process =
            Process::from_pid(pid, ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION, false)?;

        // Check if the module is already loaded in the target process first
        if let Some(entry) = process.module_entry_by_name(&name, snapshot_flags)? {
            println!("yee {} {} {:x}", name, pid, entry.hModule as usize);
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

    // We load system modules from disk because we know the file location
    // And the proc offset will be the same
    fn proc_address_external(&self, proc_name: &str) -> anyhow::Result<*const ()> {
        let proc = Process::from_pid(
            self.pid_owning,
            ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION,
            false,
        )?;

        let file_name = Path::new(&self.file_name()?).to_path_buf();
        let dll_path = if self.is_system_module()? && proc.is_wow64()? {
            system_module_path_to_wow64_path(&file_name)?
        } else {
            file_name
        };

        let dll_bytes = {
            println!("{:?}", dll_path);
            let mut file = OpenOptions::new().read(true).open(&dll_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            buf
        };

        // TODO: Cache pe inside the Module struct - running it for every proc_address is expensive
        let pe = PeFile::from_bytes(&dll_bytes)?;

        self.external_export_by_name(pe.exports()?, proc_name, self.info()?.lpBaseOfDll as usize)
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

    pub fn file_name(&self) -> anyhow::Result<String> {
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

        Ok(CString::new(buf)?.into_string()?)
    }

    pub fn is_system_module(&self) -> anyhow::Result<bool> {
        let name = self.file_name()?.to_ascii_lowercase();

        Ok(SYSTEM_MODULES
            .iter()
            .any(|sys_mod_name| name.contains(sys_mod_name)))
    }

    // Returns the rva of an export by proc name
    fn external_export_by_name<'a, Pe32, Pe64>(
        &self,
        exports: Wrap<pe32::exports::Exports<'a, Pe32>, pe64::exports::Exports<'a, Pe64>>,
        name: &str,
        mod_base_addr: usize,
    ) -> anyhow::Result<*const ()>
    where
        Pe32: pe32::Pe<'a>,
        Pe64: pe64::Pe<'a>,
    {
        let exports_by = exports.by()?;

        ensure!(
            exports_by.check_sorted()?,
            "Function exports table is not sorted"
        );

        match exports_by.name(name)? {
            Export::Symbol(&rva) => Ok((rva as usize + mod_base_addr) as *const ()),
            Export::Forward(name) => {
                // TODO: Check for ordinal forwarded exports
                let name = name.to_str()?;

                let v: Vec<&str> = name.split('.').take(2).collect();
                ensure!(
                    v.len() == 2,
                    "Named forwarded export was not formatted properly"
                );

                let (dll, fwd_proc_name) = (v.get(0).unwrap(), v.get(1).unwrap());
                let lib = Self::find_or_load_external(self.pid_owning, dll, None)?;

                lib.proc_address(fwd_proc_name)
            }
        }
    }
}

// Retrieves the WoW64 system directory
// https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-getsystemwow64directorya
pub fn get_wow64_dir() -> anyhow::Result<PathBuf> {
    let mut buf = vec![0; 0x200];
    let ret =
        unsafe { GetSystemWow64DirectoryA(buf.as_mut_ptr() as LPSTR, buf.len() as u32) } as usize;

    buf.resize(ret, 0);

    let str_dir = CString::new(buf)?.into_string()?;

    Ok(Path::new(&str_dir).to_path_buf())
}

// FIXME: incomplete
// https://docs.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
pub fn system_module_path_to_wow64_path(system_module_path: &Path) -> anyhow::Result<PathBuf> {
    let mut wow64_dir = get_wow64_dir()?;
    wow64_dir.push(
        system_module_path
            .file_name()
            .ok_or_else(|| anyhow!("Dll path has invalid format"))?,
    );

    Ok(wow64_dir)
}
