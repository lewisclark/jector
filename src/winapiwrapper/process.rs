use super::error::Error;
use super::processaccess::ProcessAccess;
use std::ops::Drop;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
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

    pub fn handle(&self) -> Result<HANDLE, Error> {
        if self.handle.is_null() {
            Err(Error::new("Attempted to retrieve NULL handle".to_string()))
        } else {
            Ok(self.handle)
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}
