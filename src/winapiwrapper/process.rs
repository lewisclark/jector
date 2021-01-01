use super::handleowner::HandleOwner;
use super::snapshot::{Snapshot, SnapshotFlags};
use super::virtualmem::ProtectFlag;
use super::WinApiError;
use std::ffi::CStr;
use std::ops::Drop;
use std::path::Path;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetProcessId, OpenProcess};
use winapi::um::tlhelp32::MODULEENTRY32;
use winapi::um::winnt::{self, HANDLE};

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn from_pid(pid: u32, access: ProcessAccess, inherit: bool) -> anyhow::Result<Self> {
        let handle = unsafe { OpenProcess(access.bits(), inherit as i32, pid) };

        ensure!(
            !handle.is_null(),
            WinApiError::FunctionCallFailure("OpenProcess".to_string())
        );

        Ok(Self { handle })
    }

    pub fn from_current() -> Self {
        unsafe { Process::from_handle(GetCurrentProcess()) }
    }

    pub fn pid(&self) -> anyhow::Result<u32> {
        let pid = unsafe { GetProcessId(self.handle) };

        ensure!(
            pid != 0,
            WinApiError::FunctionCallFailure("GetProcessId".to_string())
        );

        Ok(pid)
    }

    pub fn snapshot(&self, flags: SnapshotFlags) -> anyhow::Result<Snapshot> {
        Snapshot::from_pid(self.pid()?, flags)
    }

    pub fn write_memory(&self, data: &[u8], address: usize) -> anyhow::Result<usize> {
        ensure!(address != 0, "Attempted to write to NULL memory address");

        let (ret, num_bytes_written) = unsafe {
            let mut num_bytes_written = 0;

            let ret = WriteProcessMemory(
                self.handle(),
                address as *mut c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                &mut num_bytes_written,
            );

            (ret, num_bytes_written)
        };

        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("WriteProcessMemory".to_string())
        );

        Ok(num_bytes_written)
    }

    pub fn read_memory(&self, buffer: &mut [u8], address: usize) -> anyhow::Result<usize> {
        ensure!(address != 0, "Attempted to read from NULL memory address");
        ensure!(!buffer.is_empty(), "Buffer length is zero");

        let (ret, num_bytes_read) = unsafe {
            let mut num_bytes_read = 0;

            let ret = ReadProcessMemory(
                self.handle(),
                address as *mut c_void,
                buffer.as_ptr() as *mut c_void,
                buffer.len(),
                &mut num_bytes_read,
            );

            (ret, num_bytes_read)
        };

        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("ReadProcessMemory".to_string())
        );

        Ok(num_bytes_read)
    }

    pub fn virtual_protect(
        &self,
        address: usize,
        size: usize,
        protect: ProtectFlag,
    ) -> anyhow::Result<u32> {
        let (ret, old_protect) = unsafe {
            let mut old_protect = 0;

            (
                VirtualProtectEx(
                    self.handle,
                    address as LPVOID,
                    size,
                    protect.bits(),
                    &mut old_protect,
                ),
                old_protect,
            )
        };

        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("VirtualProtectEx".to_string())
        );

        Ok(old_protect)
    }

    // FIXME: Won't work for manually mapped modules
    pub fn module_entry_by_name(&self, name: &str) -> anyhow::Result<Option<MODULEENTRY32>> {
        // Ensure consistency - make lowercase and ensure .dll extension is present
        let name = Path::new(name)
            .with_extension("dll")
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert Path to str"))?
            .to_ascii_lowercase();

        let entry: Option<anyhow::Result<MODULEENTRY32>> = self
            .snapshot(SnapshotFlags::TH32CS_SNAPMODULE | SnapshotFlags::TH32CS_SNAPMODULE32)?
            .module_entries(self.pid()?)
            .filter_map(|entry| {
                let entry_name =
                    match unsafe { CStr::from_ptr(entry.szModule.as_ptr()) }.to_str() {
                        Ok(name) => name,
                        Err(e) => {
                            return Some(Err(anyhow!(
                                "Failed to construct CStr from MODULEENTRY32.szModule: {}",
                                e
                            )))
                        }
                    }
                    .to_ascii_lowercase();

                if entry_name == name {
                    Some(Ok(entry))
                } else {
                    None
                }
            })
            .next();

        Ok(match entry {
            Some(entry) => Some(entry?),
            None => None,
        })
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close_handle().unwrap()
    }
}

impl HandleOwner for Process {
    unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }

    fn is_handle_closable(&self) -> bool {
        // -1 is the pseudo handle for the current process and need not be closed
        self.handle as isize != -1
    }
}

// ProcessAccess flags
// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
bitflags! {
    pub struct ProcessAccess: u32 {
        const DELETE = winnt::DELETE;
        const READ_CONTROL = winnt::READ_CONTROL;
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        const WRITE_DAC = winnt::WRITE_DAC;
        const WRITE_OWNER = winnt::WRITE_OWNER;
        const PROCESS_ALL_ACCESS = winnt::PROCESS_ALL_ACCESS;
        const PROCESS_CREATE_PROCESS = winnt::PROCESS_CREATE_PROCESS;
        const PROCESS_CREATE_THREAD = winnt::PROCESS_CREATE_THREAD;
        const PROCESS_DUP_HANDLE = winnt::PROCESS_DUP_HANDLE;
        const PROCESS_QUERY_INFORMATION = winnt::PROCESS_QUERY_INFORMATION;
        const PROCESS_QUERY_LIMITED_INFORMATION = winnt::PROCESS_QUERY_LIMITED_INFORMATION;
        const PROCESS_SET_INFORMATION = winnt::PROCESS_SET_INFORMATION;
        const PROCESS_SET_QUOTA = winnt::PROCESS_SET_QUOTA;
        const PROCESS_SUSPEND_RESUME = winnt::PROCESS_SUSPEND_RESUME;
        const PROCESS_TERMINATE = winnt::PROCESS_TERMINATE;
        const PROCESS_VM_OPERATION = winnt::PROCESS_VM_OPERATION;
        const PROCESS_VM_READ = winnt::PROCESS_VM_READ;
        const PROCESS_VM_WRITE = winnt::PROCESS_VM_WRITE;
    }
}
