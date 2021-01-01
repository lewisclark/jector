use crate::winapiwrapper::module::Module;
use crate::winapiwrapper::process::{Process, ProcessAccess};
use crate::winapiwrapper::thread::{self, Thread, ThreadCreationFlags};
use crate::winapiwrapper::virtualmem::{AllocType, ProtectFlag, VirtualMem};
use dynasmrt::{dynasm, mmap::ExecutableBuffer, DynasmApi};

#[cfg(target_arch = "x86")]
use pelite::pe32::PeFile;

#[cfg(target_arch = "x86_64")]
use pelite::pe64::PeFile;

use rand::distributions::Alphanumeric;
use rand::Rng;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::mem::transmute;
use winapi::shared::minwindef::MAX_PATH;

const PTR_SIZE: usize = size_of::<usize>();

pub fn inject_library(pid: u32, path: &str) -> anyhow::Result<usize> {
    // Open a handle to the target process
    let process = Process::from_pid(
        pid,
        ProcessAccess::SYNCHRONIZE
            | ProcessAccess::PROCESS_CREATE_THREAD
            | ProcessAccess::PROCESS_QUERY_INFORMATION
            | ProcessAccess::PROCESS_VM_OPERATION
            | ProcessAccess::PROCESS_VM_WRITE
            | ProcessAccess::PROCESS_VM_READ,
        false,
    )?;

    // Allocate a buffer inside the target process to contain the path of dll
    let buffer = VirtualMem::alloc(
        &process,
        0,
        MAX_PATH as usize + PTR_SIZE,
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_READWRITE,
    )?;

    // Write file path to buffer
    let path_bytes = CString::new(path)?.into_bytes();
    buffer.write_memory(path_bytes.as_slice(), PTR_SIZE)?;

    // Obtain the address of LoadLibrary
    // TODO: Use Library::load_external when it is stable with proc_address_external
    let libkernel32 = Module::load_internal("kernel32.dll")?;
    let loadlibrary = libkernel32.proc_address("LoadLibraryA")?;

    let stub = create_stub(loadlibrary, buffer.address())?;

    // Allocate a buffer for the stub code
    let stub_buffer = VirtualMem::alloc(
        &process,
        0,
        stub.size(),
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_EXECUTE_READWRITE,
    )?;

    // Write stub to buffer
    stub_buffer.write_memory(&stub, 0)?;

    // Transmute dynamic asm to a function pointer
    let stub_fn = unsafe { transmute::<usize, thread::StartRoutine>(stub_buffer.address()) };

    // Spawn a remote thread to execute the stub
    let thr = Thread::spawn_remote(
        &process,
        None,
        stub_fn,
        None,
        ThreadCreationFlags::IMMEDIATE,
        None,
    )?;

    // Wait for the thread to finish execution
    thr.wait(10000)?;

    // Read handle from the buffer that was written by the stub
    let handle = {
        let mut buf: [u8; PTR_SIZE] = [0; PTR_SIZE];
        buffer.read_memory(&mut buf, 0)?;

        usize::from_ne_bytes(buf)
    };

    ensure!(thr.exit_code()? == 0 && handle != 0);

    Ok(handle)
}

pub fn inject(pid: u32, _pe: PeFile, image: &[u8]) -> anyhow::Result<usize> {
    // Determine file path for library
    let mut file_name: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .collect();
    file_name.push_str(".dll");

    let mut file_path = env::temp_dir();
    file_path.push(&file_name);

    ensure!(file_path.as_os_str().len() < MAX_PATH);

    let file_path = file_path.as_path();

    // Write the file to disk so that LoadLibraryA can use it
    {
        // Enclosed in braces so the lock on this file is freed for LoadLibrary to acquire
        let mut file = File::create(file_path)?;
        file.write_all(image)?;
        file.sync_data()?;
    }

    inject_library(
        pid,
        file_path
            .to_str()
            .ok_or_else(|| anyhow!("Failed to convert Path to str"))?,
    )
}

// Create the assembly for the stub that is responsible for calling LoadLibrary
#[cfg(target_arch = "x86_64")]
fn create_stub(loadlibrary: *const (), buffer_address: usize) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x64::Assembler::new()?;
    dynasm!(assembler
        ; .arch x64
        ; mov r8, QWORD loadlibrary as _                        // Move LoadLibraryA into r8
        ; mov rcx, QWORD (buffer_address + PTR_SIZE) as _     // Move library name to rcx
        ; sub rsp, 40                                         // Allocate 32 bytes of shadow space
        // Had to add 8 bytes to it because a movaps ins was crashing because of stack misalignment
        ; call r8                                               // Call LoadLibraryA
        ; add rsp, 40                                         // Reclaim shadow space
        ; mov rcx, QWORD buffer_address as _                  // Move buffer address (handle dest)
        ; mov [rcx], rax                                        // Put returned handle in handle dest
        ; xor rax, rax                                          // set rax to = 0 as ret val
        ; ret                                                   // Return to caller
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}

#[cfg(target_arch = "x86")]
fn create_stub(loadlibrary: *const (), buffer_address: usize) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x86::Assembler::new()?;
    dynasm!(assembler
        ; .arch x86
        ; push ebp
        ; mov ebp, esp
        ; lea eax, [(buffer_address + PTR_SIZE) as _]
        ; push eax
        ; mov eax, DWORD loadlibrary as _
        ; call eax
        ; lea ecx, [buffer_address as _]
        ; mov [ecx], eax
        ; xor eax, eax
        ; mov esp, ebp
        ; pop ebp
        ; ret
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}
