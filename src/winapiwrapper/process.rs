use std::ops::Drop;
use super::error::Error;
use std::ffi::c_void;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::{OpenProcess, GetCurrentProcess};
use winapi::um::winnt::HANDLE;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx};
use winapi::shared::minwindef::LPVOID;

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

	pub fn handle(&self) -> Result<HANDLE, Error> {
		if self.handle.is_null() {
			Err(Error::new("Attempted to retrieve NULL handle".to_string()))
		}
		else {
			Ok(self.handle)
		}
	}
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}

// VirtualMem

pub struct VirtualMem<'a> {
	process: &'a Process,
	address: *const c_void,
	size: usize
}

impl<'a> VirtualMem<'a> {
        pub fn alloc(process: &'a Process, address: usize, size: usize, alloc_type: u32, protect: u32) -> Result<Self, Error> {
			let mem = unsafe {
				VirtualAllocEx(process.handle()?, address as LPVOID, size, alloc_type, protect)
			};

			if mem.is_null() {
				Err(Error::new("VirtualAllocEx returned NULL".to_string()))
			}
			else {
				Ok(Self {
					process: process,
					address: mem as *const c_void,
					size: size
				})
			}
        }

        pub fn free(&mut self, freetype: u32) -> Result<(), Error> {
			if self.address.is_null() {
				return Err(Error::new("Tried to free null virtual memory region".to_string()));
			}


			let ret = unsafe {
				VirtualFreeEx(self.process.handle()?, self.address as LPVOID, self.size, freetype)
			};

			if ret == 0 {
				Err(Error::new("VirtualFreeEx failed".to_string()))
			}
			else {
				Ok(())
			}
        }
}

impl Drop for VirtualMem<'_> {
        fn drop(&mut self) {

        }
}
