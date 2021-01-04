use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::{self, Thread32First, Thread32Next, THREADENTRY32};
use winapi::um::winnt::HANDLE;

// CreateToolhelp32Snapshot flags
// https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
bitflags! {
    pub struct SnapshotFlags: u32 {
        const TH32CS_INHERIT = tlhelp32::TH32CS_INHERIT;
        const TH32CS_SNAPALL = tlhelp32::TH32CS_SNAPALL;
        const TH32CS_SNAPHEAPLIST = tlhelp32::TH32CS_SNAPHEAPLIST;
        const TH32CS_SNAPMODULE = tlhelp32::TH32CS_SNAPMODULE;
        const TH32CS_SNAPMODULE32 = tlhelp32::TH32CS_SNAPMODULE32;
        const TH32CS_SNAPPROCESS = tlhelp32::TH32CS_SNAPPROCESS;
        const TH32CS_SNAPTHREAD = tlhelp32::TH32CS_SNAPTHREAD;
    }
}

// Snapshot struct
pub struct Snapshot {
    handle: HANDLE,
}

impl Snapshot {
    pub unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    pub fn from_pid(pid: u32, flags: SnapshotFlags) -> anyhow::Result<Self> {
        let h = unsafe { CreateToolhelp32Snapshot(flags.bits(), pid) };
        ensure!(
            h != INVALID_HANDLE_VALUE,
            function_call_failure!("CreateToolhelp32Snapshot"),
        );

        Ok(unsafe { Self::from_handle(h) })
    }

    pub fn close(&self) -> anyhow::Result<()> {
        // -1 is the pseudo handle for the current process and need not be closed
        if self.handle as isize != 1 {
            let ret = unsafe { CloseHandle(self.handle) };

            ensure!(ret != 0, function_call_failure!("CloseHandle"));
        }

        Ok(())
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}

// SnapshotThreadEntries
pub struct SnapshotThreadEntries {
    snapshot: Snapshot,
    is_first: bool,
}

impl Iterator for SnapshotThreadEntries {
    type Item = THREADENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        let mut thread_entry = THREADENTRY32::default();

        let ret = if self.is_first {
            self.is_first = false;

            unsafe { Thread32First(self.snapshot.handle, &mut thread_entry) }
        } else {
            unsafe { Thread32Next(self.snapshot.handle, &mut thread_entry) }
        };

        match ret {
            0 => None,
            _ => Some(thread_entry),
        }
    }
}
