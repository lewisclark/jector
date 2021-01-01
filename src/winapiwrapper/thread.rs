use super::handleowner::HandleOwner;
use super::process::Process;
use super::threadcreationflags::ThreadCreationFlags;
use super::WinApiError;
use std::ffi::c_void;
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::WAIT_FAILED;
use winapi::um::winnt::HANDLE;

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;

pub struct Thread {
    handle: HANDLE,
}

impl Thread {
    pub fn spawn_remote(
        process: &Process,
        stack_size: Option<usize>,
        routine: StartRoutine,
        param: Option<*mut c_void>,
        creation_flags: ThreadCreationFlags,
        thread_id: Option<&mut u32>,
    ) -> anyhow::Result<Self> {
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
                process.handle(),
                ptr::null_mut(),
                stack_size.unwrap_or(0),
                Some(routine),
                param,
                creation_flags.bits(),
                thread_id,
            )
        };

        ensure!(
            !handle.is_null(),
            WinApiError::FunctionCallFailure("CreateRemoteThread".to_string())
        );

        Ok(Self { handle })
    }

    pub fn exit_code(&self) -> anyhow::Result<u32> {
        let mut code = 0;
        let ret = unsafe { GetExitCodeThread(self.handle, &mut code) };
        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("GetExitCodeThread".to_string())
        );

        Ok(code)
    }

    pub fn wait(&self, timeout: u32) -> anyhow::Result<u32> {
        let ret = unsafe { WaitForSingleObject(self.handle, timeout) };
        ensure!(
            ret != WAIT_FAILED,
            WinApiError::FunctionCallFailure("WaitForSingleObject".to_string())
        );

        Ok(ret)
    }
}

impl HandleOwner for Thread {
    unsafe fn from_handle(handle: HANDLE) -> Thread {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }

    fn is_handle_closable(&self) -> bool {
        false
    }
}
