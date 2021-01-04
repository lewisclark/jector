use super::process::Process;
use super::snapshot::{Snapshot, SnapshotFlags};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::TRUE;
use winapi::um::processthreadsapi::{CreateRemoteThread, GetExitCodeThread};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::{Thread32First, Thread32Next, THREADENTRY32};
use winapi::um::winbase::{self, WAIT_FAILED};
use winapi::um::winnt::{self, HANDLE};

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;

// Thread security and access rights
// https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
bitflags! {
    pub struct ThreadAccess: u32 {
        const DELETE = winnt::DELETE;
        const READ_CONTROL = winnt::READ_CONTROL;
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        const WRITE_DAC = winnt::WRITE_DAC;
        const WRITE_OWNER = winnt::WRITE_OWNER;
        const THREAD_ALL_ACCESS = winnt::THREAD_ALL_ACCESS;
        const THREAD_DIRECT_IMPERSONATION = winnt::THREAD_DIRECT_IMPERSONATION;
        const THREAD_GET_CONTEXT = winnt::THREAD_GET_CONTEXT;
        const THREAD_IMPERSONATE = winnt::THREAD_IMPERSONATE;
        const THREAD_QUERY_INFORMATION = winnt::THREAD_QUERY_INFORMATION;
        const THREAD_QUERY_LIMITED_INFORMATION = winnt::THREAD_QUERY_LIMITED_INFORMATION;
        const THREAD_SET_CONTEXT = winnt::THREAD_SET_CONTEXT;
        const THREAD_SET_INFORMATION = winnt::THREAD_SET_INFORMATION;
        const THREAD_SET_LIMITED_INFORMATION = winnt::THREAD_SET_LIMITED_INFORMATION;
        const THREAD_SET_THREAD_TOKEN = winnt::THREAD_SET_THREAD_TOKEN;
        const THREAD_SUSPEND_RESUME = winnt::THREAD_SUSPEND_RESUME;
        const THREAD_TERMINATE = winnt::THREAD_TERMINATE;
    }
}

// Thread creation flags
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
bitflags! {
    pub struct ThreadCreationFlags: u32 {
        const IMMEDIATE = 0;
        const CREATE_SUSPENDED = winbase::CREATE_SUSPENDED;
    }
}

// Thread struct
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
            function_call_failure!("CreateRemoteThread"),
        );

        Ok(Self { handle })
    }

    pub fn exit_code(&self) -> anyhow::Result<u32> {
        let mut code = 0;
        let ret = unsafe { GetExitCodeThread(self.handle, &mut code) };
        ensure!(ret != 0, function_call_failure!("GetExitCodeThread"),);

        Ok(code)
    }

    pub fn wait(&self, timeout: u32) -> anyhow::Result<u32> {
        let ret = unsafe { WaitForSingleObject(self.handle, timeout) };
        ensure!(
            ret != WAIT_FAILED,
            function_call_failure!("WaitForSingleObject"),
        );

        Ok(ret)
    }
}

// Threads struct
// Iterates over a process's threads using a snapshot
pub struct Threads {
    snapshot: Snapshot,
    is_first: bool,
}

impl Threads {
    pub fn new(pid: u32) -> anyhow::Result<Self> {
        let snapshot = Snapshot::from_pid(pid, SnapshotFlags::TH32CS_SNAPTHREAD)?;

        Ok(Self {
            snapshot,
            is_first: true,
        })
    }
}

impl Iterator for Threads {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = THREADENTRY32::default();
        entry.dwSize = size_of::<THREADENTRY32>() as u32;

        let ret = unsafe {
            match self.is_first {
                true => {
                    self.is_first = false;
                    Thread32First(self.snapshot.handle(), &mut entry)
                }
                false => Thread32Next(self.snapshot.handle(), &mut entry),
            }
        };

        if ret == TRUE {
            Some(entry.th32ThreadID)
        } else {
            None
        }
    }
}
