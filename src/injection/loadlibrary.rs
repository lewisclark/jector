use crate::winapiwrapper::module::Module;
use crate::winapiwrapper::process::{Process, ProcessAccess};
use crate::winapiwrapper::thread::{self, Thread, ThreadCreationFlags};
use crate::winapiwrapper::virtualmem::{AllocType, ProtectFlag, VirtualMem};
use dynasmrt::{dynasm, mmap::ExecutableBuffer, DynasmApi};
use pelite::PeFile;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::mem::{size_of, transmute};
use std::path::Path;
use winapi::shared::minwindef::MAX_PATH;

pub fn inject_library(pid: u32, path: &Path) -> anyhow::Result<usize> {
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

    let is_wow64 = process.is_wow64()?;
    let remote_process_ptr_size = if is_wow64 {
        size_of::<u32>()
    } else {
        size_of::<u64>()
    };

    // Allocate a buffer inside the target process to contain the path of dll
    let buffer = VirtualMem::alloc(
        &process,
        0,
        MAX_PATH as usize + remote_process_ptr_size,
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_READWRITE,
    )?;

    // Write file path to buffer
    let path_bytes =
        CString::new(path.to_str().ok_or_else(|| anyhow!("Failed to convert"))?)?.into_bytes();
    buffer.write_memory(path_bytes.as_slice(), remote_process_ptr_size)?;

    // Obtain the address of LoadLibrary
    let libkernel32 = Module::find_or_load_external(process.pid()?, Path::new("kernel32.dll"))?;
    let loadlibrary = libkernel32.proc_address("LoadLibraryA")?;

    let stub = match is_wow64 {
        true => create_stub_32(loadlibrary, buffer.address()),
        false => create_stub_64(loadlibrary, buffer.address()),
    }?;

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
    thr.wait(99999999)?;

    // Read handle from the buffer that was written by the stub
    let handle = {
        if is_wow64 {
            let mut buf = [0; size_of::<u32>()];
            buffer.read_memory(&mut buf, 0)?;

            u32::from_ne_bytes(buf) as usize
        } else {
            let mut buf = [0; size_of::<u64>()];
            buffer.read_memory(&mut buf, 0)?;

            u64::from_ne_bytes(buf) as usize
        }
    };

    ensure!(thr.exit_code()? == 0);
    ensure!(handle != 0, "LoadLibraryA returned a NULL handle");

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

    inject_library(pid, file_path)
}

// Create the assembly for the stub that is responsible for calling LoadLibrary
fn create_stub_64(loadlibrary: usize, buffer_address: usize) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x64::Assembler::new()?;
    dynasm!(assembler
        ; .arch x64
        ; mov r8, QWORD loadlibrary as _                        // Move LoadLibraryA into r8
        ; mov rcx, QWORD (buffer_address + size_of::<u64>()) as _     // Move library name to rcx
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

fn create_stub_32(loadlibrary: usize, buffer_address: usize) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x86::Assembler::new()?;
    dynasm!(assembler
        ; .arch x86
        ; push ebp
        ; mov ebp, esp
        ; lea eax, [(buffer_address + size_of::<u32>()) as _]
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
