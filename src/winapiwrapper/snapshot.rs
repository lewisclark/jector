use super::error::Error;
use super::handleowner::HandleOwner;
use super::snapshotflags::SnapshotFlags;
use std::mem::size_of;
use winapi::shared::minwindef::{BYTE, HMODULE};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::{
    Module32First, Module32Next, Thread32First, Thread32Next, MODULEENTRY32, THREADENTRY32,
};
use winapi::um::winnt::HANDLE;

// TODO: Clean up snapshot with CloseHandle

pub struct Snapshot {
    handle: HANDLE,
}

impl Snapshot {
    pub fn from_pid(pid: u32, flags: SnapshotFlags) -> Result<Self, Error> {
        let h = unsafe { CreateToolhelp32Snapshot(flags.bits(), pid) };

        if h != INVALID_HANDLE_VALUE {
            Ok(unsafe { Self::from_handle(h) })
        } else {
            Err(Error::new(
                "CreateToolhelp32Snapshot returned an invalid handle".to_string(),
            ))
        }
    }

    pub fn thread_entries(self) -> SnapshotThreadEntries {
        SnapshotThreadEntries::new(self)
    }

    pub fn module_entries(self) -> SnapshotModuleEntries {
        SnapshotModuleEntries::new(self)
    }
}

impl HandleOwner for Snapshot {
    unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

// SnapshotThreadEntries
pub struct SnapshotThreadEntries {
    snapshot: Snapshot,
    is_first: bool,
}

impl SnapshotThreadEntries {
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot,
            is_first: true,
        }
    }
}

impl Iterator for SnapshotThreadEntries {
    type Item = THREADENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        let mut thread_entry = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };

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
    is_first: bool,
}

impl SnapshotModuleEntries {
    pub fn new(snapshot: Snapshot) -> Self {
        Self {
            snapshot,
            is_first: true,
        }
    }
}

impl Iterator for SnapshotModuleEntries {
    type Item = MODULEENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = MODULEENTRY32 {
            dwSize: size_of::<MODULEENTRY32>() as u32,
            th32ModuleID: 0,
            th32ProcessID: 0,
            GlblcntUsage: 0,
            ProccntUsage: 0,
            modBaseAddr: 0 as *mut BYTE,
            modBaseSize: 0,
            hModule: 0 as HMODULE,
            szModule: [0; 256],
            szExePath: [0; 260],
        };

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
