use super::error::Error;
use super::handleowner::HandleOwner;
use super::module::Module;
use super::process::Process;
use super::securityattributes::SecurityAttributes;
use super::threadaccess::ThreadAccess;
use super::threadcreationflags::ThreadCreationFlags;
use std::ffi::c_void;
use std::mem::{size_of, transmute};
use std::ptr;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{PULONG, ULONG};
use winapi::shared::ntdef::NTSTATUS;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::processthreadsapi::{
    CreateRemoteThread, GetExitCodeThread, OpenThread, ResumeThread, THREAD_INFORMATION_CLASS,
};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winbase::WAIT_FAILED;
use winapi::um::winnt::{HANDLE, NT_TIB, PVOID};

pub type StartRoutine = unsafe extern "system" fn(*mut winapic_void) -> u32;
type NtQueryInformationThreadFn =
    unsafe extern "system" fn(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG) -> NTSTATUS;

#[repr(C)]
#[allow(non_snake_case)]
pub struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct THREAD_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub TebBaseAddress: PVOID,
    pub ClientId: CLIENT_ID,
    pub AffinityMask: u32,
    pub Priority: u32,
    pub BasePriority: u32,
}

#[repr(C)]
#[allow(non_snake_case)]
pub struct TEB {
    pub Tib: NT_TIB,
    pub EnvironmentPointer: PVOID,
    pub Cid: CLIENT_ID,
    pub ActiveRpcInfo: PVOID,
    pub ThreadLocalStoragePointer: PVOID,
    // This struct isn't entirely filled out
}

pub struct Thread {
    handle: HANDLE,
}

impl Thread {
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
                process.handle(),
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

    pub fn query_information(&self) -> Result<THREAD_BASIC_INFORMATION, Error> {
        let nt_query_information_thread = unsafe {
            transmute::<*const (), NtQueryInformationThreadFn>(
                Module::load_internal("ntdll.dll")?.proc_address("NtQueryInformationThread")?,
            )
        };

        let mut thread_basic_info = THREAD_BASIC_INFORMATION {
            ExitStatus: 0,
            TebBaseAddress: 0 as PVOID,
            ClientId: CLIENT_ID {
                UniqueProcess: 0 as HANDLE,
                UniqueThread: 0 as HANDLE,
            },
            AffinityMask: 0,
            Priority: 0,
            BasePriority: 0,
        };

        let ntstatus = unsafe {
            nt_query_information_thread(
                self.handle,
                0,
                &mut thread_basic_info as *const THREAD_BASIC_INFORMATION as PVOID,
                size_of::<THREAD_BASIC_INFORMATION>() as u32,
                0 as PULONG,
            )
        };

        if ntstatus >= 0 {
            Ok(thread_basic_info)
        } else {
            Err(Error::new(format!(
                "NtQueryInformationThread returned failure NT status code: {:x}",
                ntstatus
            )))
        }
    }

    pub fn teb(&self) -> Result<*const TEB, Error> {
        let teb_ptr = self.query_information()?.TebBaseAddress;

        if teb_ptr as usize != 0 {
            Ok(teb_ptr as *const TEB)
        } else {
            Err(Error::new("TebBaseAddress is NULL".to_string()))
        }
    }

    pub fn resume(&self) -> Result<(), Error> {
        let ret = unsafe { ResumeThread(self.handle()) } as i32;

        if ret != -1 {
            Ok(())
        } else {
            Err(Error::new("ResumeThread failed".to_string()))
        }
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
