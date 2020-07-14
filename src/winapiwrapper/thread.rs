use super::error::Error;
use super::process::Process;
use super::securityattributes::SecurityAttributes;
use super::threadcreationflags::ThreadCreationFlags;
use super::threadaccess::ThreadAccess;
use std::ffi::c_void;
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread, OpenThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::WAIT_FAILED;
use winapi::um::winnt::HANDLE;

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;

pub struct Thread {
    handle: HANDLE,
}

impl Thread {
    pub unsafe fn from_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    pub fn from_id(id: u32, access: ThreadAccess, inherit_handle: bool) -> Result<Self, Error> {
        let handle = unsafe { OpenThread(access.bits(), inherit_handle as i32, id) };

        if handle.is_null() {
            Err(Error::new("OpenThread returned NULL".to_string()))
        } else {
            Ok(unsafe { Self::from_handle(handle) })
        }
    }

    pub fn spawn_remote(
        process: &Process,
        thread_attributes: Option<&SecurityAttributes>,
        stack_size: Option<usize>,
        routine: StartRoutine,
        param: Option<*mut c_void>,
        creation_flags: ThreadCreationFlags,
        thread_id: Option<&mut u32>,
    ) -> Result<Self, Error> {
        let thread_attributes = match thread_attributes {
            Some(att) => att,
            None => ptr::null(),
        } as *mut SECURITY_ATTRIBUTES;

        let thread_id = match thread_id {
            Some(id) => id,
            None => ptr::null(),
        } as *mut u32;

        let param = match param {
            Some(p) => p,
            None => ptr::null(),
        } as *mut winapic_void;

        let handle = unsafe {
            CreateRemoteThread(
                process.handle()?,
                thread_attributes,
                stack_size.unwrap_or(0),
                Some(routine),
                param,
                creation_flags.bits(),
                thread_id,
            )
        };

        if handle.is_null() {
            Err(Error::new("CreateRemoteThread returned NULL".to_string()))
        } else {
            Ok(Self { handle })
        }
    }

    pub fn exit_code(&self) -> Result<u32, Error> {
        let mut code = 0;
        let ret = unsafe { GetExitCodeThread(self.handle, &mut code) };

        if ret == 0 {
            Err(Error::new("GetExitCodeThread failed".to_string()))
        } else {
            Ok(code)
        }
    }

    pub fn wait(&self, timeout: u32) -> Result<u32, Error> {
        let ret = unsafe { WaitForSingleObject(self.handle, timeout) };

        if ret == WAIT_FAILED {
            Err(Error::new("WaitForSingleObject failed".to_string()))
        } else {
            Ok(ret)
        }
    }
}
