use super::error::Error;
use super::process::Process;
use super::securityattributes::SecurityAttributes;
use super::threadcreationflags::ThreadCreationFlags;
use std::ffi::c_void;
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::CreateRemoteThread;
use winapi::um::winnt::HANDLE;

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;

pub struct RemoteThread {
    handle: HANDLE,
}

impl RemoteThread {
    pub fn new(
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
}
