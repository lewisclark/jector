use super::handleowner::HandleOwner;
use std::mem::size_of;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::{
    self, Module32First, Module32Next, Thread32First, Thread32Next, MODULEENTRY32, THREADENTRY32,
};
use winapi::um::winnt::HANDLE;

pub struct Snapshot {
    handle: HANDLE,
}

impl Snapshot {
    pub fn from_pid(pid: u32, flags: SnapshotFlags) -> anyhow::Result<Self> {
        let h = unsafe { CreateToolhelp32Snapshot(flags.bits(), pid) };
        ensure!(
            h != INVALID_HANDLE_VALUE,
            function_call_failure!("CreateToolhelp32Snapshot"),
        );

        Ok(unsafe { Self::from_handle(h) })
    }

    pub fn module_entries(self, pid: u32) -> SnapshotModuleEntries {
        SnapshotModuleEntries::new(self, pid)
    }
}

impl HandleOwner for Snapshot {
    unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }

    fn is_handle_closable(&self) -> bool {
        true
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        self.close_handle().unwrap();
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

            unsafe { Thread32First(self.snapshot.handle(), &mut thread_entry) }
        } else {
            unsafe { Thread32Next(self.snapshot.handle(), &mut thread_entry) }
        };

        match ret {
            0 => None,
            _ => Some(thread_entry),
        }
    }
}

// SnapshotModuleEntries
pub struct SnapshotModuleEntries {
    snapshot: Snapshot,
    pid: u32,
    is_first: bool,
}

impl SnapshotModuleEntries {
    pub fn new(snapshot: Snapshot, pid: u32) -> Self {
        Self {
            snapshot,
            pid,
            is_first: true,
        }
    }
}

impl Iterator for SnapshotModuleEntries {
    type Item = MODULEENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = MODULEENTRY32::default();
        entry.th32ProcessID = self.pid;
        entry.dwSize = size_of::<MODULEENTRY32>() as u32;

        let ret = if self.is_first {
            self.is_first = false;

            unsafe { Module32First(self.snapshot.handle(), &mut entry) }
        } else {
            unsafe { Module32Next(self.snapshot.handle(), &mut entry) }
        };

        match ret {
            0 => None,
            _ => Some(entry),
        }
    }
}

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
