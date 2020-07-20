use super::injector::Injector;
use crate::error::Error;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::library::Library;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::thread::{self, Thread};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use pelite::pe64::PeFile;
use std::env;
use std::ffi::c_void;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::mem::transmute;
use winapi::shared::minwindef::MAX_PATH;

pub struct LoadLibraryInjector {}

impl Injector for LoadLibraryInjector {
    fn inject(pid: u32, _pe: PeFile, image: &[u8]) -> Result<usize, Box<dyn std::error::Error>> {
        // Determine file path for library
        let mut file_path = env::temp_dir();
        file_path.push("image.dll"); // TODO: Randomize file name
        let file_path = file_path.as_path();
        // TODO: Ensure file_path length does not exceed (MAX_PATH - 1) nul byte

        // Write the file to disk so that LoadLibraryA can use it
        let mut file = File::create(file_path)?;
        file.write_all(image)?;
        file.sync_data()?;

        // Open a handle to the target process
        let process = Process::from_pid(
            pid,
            ProcessAccess::SYNCHRONIZE
                | ProcessAccess::PROCESS_CREATE_THREAD
                | ProcessAccess::PROCESS_QUERY_INFORMATION
                | ProcessAccess::PROCESS_VM_OPERATION
                | ProcessAccess::PROCESS_VM_WRITE,
            false,
        )?;

        // Allocate a buffer inside the target process to contain the path of dll
        let buffer = VirtualMem::alloc(
            &process,
            0,
            MAX_PATH as usize,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_READWRITE,
        )?;

        // Write file path to buffer
        let path_bytes = CString::new(file_path.to_str().ok_or(Box::new(Error::new(
            "Failed to convert file path to str".to_string(),
        )))?)?
        .into_bytes();
        buffer.write_memory(path_bytes.as_slice(), 0)?;

        // Obtain the address of LoadLibrary
        // TODO: Use Library::load_external when it is stable with proc_address_external
        let libkernel32 = Library::load("kernel32.dll")?;
        let loadlibrary = libkernel32.proc_address("LoadLibraryA")?;

        // Transmute loadlibrary into the start routine signature
        let loadlibrary = unsafe { transmute::<*const (), thread::StartRoutine>(loadlibrary) };

        // Spawn a remote thread to execute LoadLibrary
        let thr = Thread::spawn_remote(
            &process,
            None,
            None,
            loadlibrary,
            Some(buffer.address() as *mut c_void),
            ThreadCreationFlags::IMMEDIATE,
            None,
        )?;

        // Wait for the thread to finish execution
        thr.wait(10000)?;

        // Clean up image file
        fs::remove_file(file_path)?;

        // Obtain thread exit code
        let loadlibrary_ret = thr.exit_code()?;

        if loadlibrary_ret != 0 {
            Ok(loadlibrary_ret as usize)
        } else {
            Err(Box::new(Error::new(
                "LoadLibrary injection returned NULL".to_string(),
            )))
        }
    }
}
