use super::error::Error;
use super::handleowner::HandleOwner;
use super::processaccess::ProcessAccess;
use super::snapshot::Snapshot;
use super::snapshotflags::SnapshotFlags;
use super::thread::Thread;
use super::threadaccess::ThreadAccess;
use std::ops::Drop;
use winapi::ctypes::c_void;
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::{GetProcessId, OpenProcess};
use winapi::um::winnt::HANDLE;

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn from_pid(pid: u32, access: ProcessAccess, inherit: bool) -> Result<Self, Error> {
        let handle = unsafe { OpenProcess(access.bits(), inherit as i32, pid) };

        if handle.is_null() {
            Err(Error::new("OpenProcess returned NULL".to_string()))
        } else {
            Ok(Self { handle })
        }
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if self.handle.is_null() {
            return Err(Error::new(
                "Null handle passed to Process::close".to_string(),
            ));
        }

        let ret = unsafe { CloseHandle(self.handle) };

        if ret == 0 {
            Err(Error::new("CloseHandle failed".to_string()))
        } else {
            self.handle = 0 as HANDLE;
            Ok(())
        }
    }

    pub fn pid(&self) -> Result<u32, Error> {
        let pid = unsafe { GetProcessId(self.handle) };

        if pid == 0 {
            Err(Error::new("GetProcessId returned NULL".to_string()))
        } else {
            Ok(pid)
        }
    }

    pub fn snapshot(&self, flags: SnapshotFlags) -> Result<Snapshot, Error> {
        Snapshot::from_pid(self.pid()?, flags)
    }

    // FIXME: This returns the first thread of many. Maybe turn it into an iterator?
    pub fn main_thread(
        &self,
        access: ThreadAccess,
        inherit_handle: bool,
    ) -> Result<Option<Thread>, Error> {
        let snapshot = self.snapshot(SnapshotFlags::TH32CS_SNAPTHREAD)?;
        let pid = self.pid()?;

        for thread_entry in snapshot.thread_entries() {
            if pid == thread_entry.th32OwnerProcessID {
                return Ok(Some(Thread::from_id(
                    thread_entry.th32ThreadID,
                    access,
                    inherit_handle,
                )?));
            }
        }

        Ok(None)
    }

    pub fn write_memory(&self, data: &[u8], address: usize) -> Result<usize, Error> {
        if address == 0 {
            return Err(Error::new("Address to write to is null".to_string()));
        }

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

        if ret == 0 {
            Err(Error::new("WriteProcesMemory failed".to_string()))
        } else {
            Ok(num_bytes_written)
        }
    }

    pub fn read_memory(&self, buffer: &mut [u8], address: usize) -> Result<usize, Error> {
        if address == 0 {
            return Err(Error::new("Address to read from is null".to_string()));
        } else if buffer.is_empty() {
            return Err(Error::new("Buffer length is zero".to_string()));
        }

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

        if ret == 0 {
            Err(Error::new("ReadProcessMemory failed".to_string()))
        } else {
            Ok(num_bytes_read)
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}

impl HandleOwner for Process {
    unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}
