use std::ops::Drop;
use super::error::Error;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess};
use winapi::um::winnt::HANDLE;

// Process

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn from_pid(pid: u32, access: u32, inherit: bool) -> Result<Self, Error> {
        let handle = unsafe { OpenProcess(access, inherit as i32, pid) };

		if handle.is_null() {
			Err(Error::new("OpenProcess returned NULL".to_string()))
		}
		else {
			Ok(Self { handle })
		}
    }

	pub fn from_current() -> Result<Self, Error> {
		let handle = unsafe { GetCurrentProcess() };

		if handle.is_null() {
			Err(Error::new("OpenProcess returned NULL".to_string()))
		}
		else {
			Ok(Self { handle })
		}
	}

    pub fn close(&mut self) -> Result<(), Error> {
        if self.handle.is_null() {
            return Err(Error::new("Null handle passed to Process::close".to_string()));
        }

        let ret = unsafe { CloseHandle(self.handle) };

		if ret == 0 {
			Err(Error::new("CloseHandle failed".to_string()))
		}
		else {
			self.handle = 0 as HANDLE;
			Ok(())
		}
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}

// VirtualMem

pub struct VirtualMem {

}

impl VirtualMem {
        pub fn alloc(process: Process, address: *const c_void, size: usize, alloc_type: usize, protect: usize) {


        }

        pub fn free(&mut self) {

        }
}

impl Drop for VirtualMem {
        fn drop(&mut self) {

        }
}
