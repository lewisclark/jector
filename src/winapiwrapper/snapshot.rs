use super::error::Error;
use super::snapshotflags::SnapshotFlags;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::tlhelp32::CreateToolhelp32Snapshot;
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

        if h == INVALID_HANDLE_VALUE {
            Ok(unsafe { Self::from_handle(h) })
        } else {
            Err(Error::new(
                "CreateToolhelp32Snapshot returned an invalid handle".to_string(),
            ))
        }
    }
}
