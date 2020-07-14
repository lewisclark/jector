use super::error::Error;
use super::snapshotflags::SnapshotFlags;
use super::thread::Thread;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
use winapi::um::tlhelp32::{Thread32First, Thread32Next, THREADENTRY32};
use winapi::um::winnt::HANDLE;

pub struct Snapshot {
    handle: HANDLE,
}

impl Snapshot {
    pub unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

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

    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    pub fn thread_entries(self) -> SnapshotThreadEntries {
        SnapshotThreadEntries::new(self)
    }
}

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
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
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
