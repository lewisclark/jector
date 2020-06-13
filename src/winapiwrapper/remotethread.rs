use super::error::Error;
use super::process::Process;
use super::securityattributes::SecurityAttributes;
use std::ffi::c_void;
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::CreateRemoteThread;

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;

pub struct RemoteThread {}

impl RemoteThread {
    pub fn new(
        process: &Process,
        thread_attributes: Option<&SecurityAttributes>,
        stack_size: usize,
        routine: StartRoutine,
        param: *mut c_void,
        creation_flags: u32,
        thread_id: *mut u32,
    ) -> Result<Self, Error> {
        let handle = unsafe {
            let thread_attributes = match thread_attributes {
                Some(att) => att,
                None => ptr::null(),
            } as *mut SECURITY_ATTRIBUTES;

            CreateRemoteThread(
                process.handle()?,
                thread_attributes,
                stack_size,
                Some(routine),
                param as *mut winapic_void,
                creation_flags,
                thread_id,
            )
        };

        if handle.is_null() {
            Err(Error::new("CreateRemoteThread returned NULL".to_string()))
        } else {
            Ok(Self {})
        }
    }
}
