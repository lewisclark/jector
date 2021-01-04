use crate::winapiwrapper::module::Module;
use crate::winapiwrapper::process::{Process, ProcessAccess};
use crate::winapiwrapper::thread::{self, Thread, ThreadCreationFlags};
use crate::winapiwrapper::virtualmem::{AllocType, ProtectFlag, VirtualMem};
use dynasmrt::{dynasm, DynasmApi, DynasmLabelApi, ExecutableBuffer};
use pelite::{image::IMAGE_DIRECTORY_ENTRY_EXCEPTION, pe64::imports::Import, PeFile, Wrap};
use std::{ffi::c_void, mem, path::Path, slice};
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_REL_BASED_ABSOLUTE, IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGHLOW,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PRUNTIME_FUNCTION,
};

type FnDllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnRtlAddFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION, u32, u64) -> u8;

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY_BASE {
    pad: [u8; 0x30],
    dll_base: usize,
}

pub fn inject(pid: u32, pe: PeFile, image: &[u8]) -> anyhow::Result<usize> {
    let (is_wow64, pe_size, pref_image_base, size_of_headers, entry_point_offset) =
        match pe.optional_header() {
            Wrap::T32(header32) => (
                true,
                header32.SizeOfImage as usize,
                header32.ImageBase as usize,
                header32.SizeOfHeaders as usize,
                header32.AddressOfEntryPoint as usize,
            ),
            Wrap::T64(header64) => (
                false,
                header64.SizeOfImage as usize,
                header64.ImageBase as usize,
                header64.SizeOfHeaders as usize,
                header64.AddressOfEntryPoint as usize,
            ),
        };

    // Obtain target process handle
    let process = Process::from_pid(
        pid,
        ProcessAccess::PROCESS_CREATE_THREAD
            | ProcessAccess::PROCESS_QUERY_INFORMATION
            | ProcessAccess::PROCESS_VM_OPERATION
            | ProcessAccess::PROCESS_VM_READ
            | ProcessAccess::PROCESS_VM_WRITE
            | ProcessAccess::SYNCHRONIZE,
        false,
    )?;

    // Allocate a buffer inside target process for the image
    // Tries to allocate at the preferred base first. Allocates elsewhere if that fails.
    let mut image_mem = match VirtualMem::alloc(
        &process,
        pref_image_base,
        pe_size,
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_EXECUTE_READWRITE,
    ) {
        Ok(mem) => Ok(mem),
        Err(_) => VirtualMem::alloc(
            &process,
            0,
            pe_size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        ),
    }?;

    image_mem.set_free_on_drop(false);

    let image_base = image_mem.address();
    let image_delta = image_base.wrapping_sub(pref_image_base);

    println!(
        "Allocated image buffer at {:x} with size {:x}",
        image_base,
        image_mem.size(),
    );

    // Write image headers
    image_mem.write_memory(&image[..size_of_headers], 0)?;

    // Write image sections
    for section in pe.section_headers() {
        let start = section.PointerToRawData as usize;
        let end = start.wrapping_add(section.SizeOfRawData as usize);

        image_mem.write_memory(&image[start..end], section.VirtualAddress as usize)?;

        println!(
            "Section {} -> {:x} with size {:x}",
            section.name().unwrap(),
            image_base.wrapping_add(section.VirtualAddress as usize),
            section.VirtualSize,
        );
    }

    // Do base relocation
    if image_delta != 0 {
        println!("Performing base relocation");

        for block in pe.base_relocs()?.iter_blocks() {
            println!("Beginning block {:x}", block.image().VirtualAddress);

            for word in block.words() {
                let typ = block.type_of(word) as u16;
                let rva = block.rva_of(word) as usize;

                match typ {
                    IMAGE_REL_BASED_ABSOLUTE => {
                        println!("Skipping base relocation for type ABSOLUTE")
                    }
                    IMAGE_REL_BASED_DIR64 => {
                        let mut buf = [0_u8; 8];
                        image_mem.read_memory(&mut buf, rva)?;

                        let p = u64::from_ne_bytes(buf).wrapping_add(image_delta as u64);
                        image_mem.write_memory(&p.to_ne_bytes(), rva)?;

                        println!("Performed DIR64 base relocation at rva {:x}", rva);
                    }
                    IMAGE_REL_BASED_HIGHLOW => {
                        let mut buf = [0_u8; 4];
                        image_mem.read_memory(&mut buf, rva)?;

                        let p = u32::from_ne_bytes(buf).wrapping_add(image_delta as u32);
                        image_mem.write_memory(&p.to_ne_bytes(), rva)?;

                        println!("Performed HIGHLOW base relocation at rva {:x}", rva);
                    }
                    _ => unimplemented!("Base relocation type: {:x}", typ),
                };
            }
        }
    } else {
        println!("Base relocation not necessary");
    }

    // Resolve imports
    for descriptor in pe.imports()? {
        let module_path = descriptor.dll_name()?.to_str()?.to_ascii_lowercase();
        let module_path = Path::new(&module_path);
        let module = Module::find_or_load_external(pid, &module_path)?;

        let mut thunk = descriptor.image().FirstThunk as usize;
        for import in descriptor.int()? {
            let import_address = match import? {
                Import::ByName { hint: _, name } => {
                    let proc_name = name.to_str()?;
                    let proc_addr = module.proc_address(proc_name)?;

                    if is_wow64 {
                        println!("mdoule {:x}", module.info()?.lpBaseOfDll as usize);
                        ensure!(
                            proc_addr <= u32::max_value() as usize,
                            anyhow!(
                                "Received 64-bit proc address for wow64 process: {:?}:{} at {:x}",
                                module_path,
                                proc_name,
                                proc_addr
                            )
                        );
                    }

                    println!(
                        "Import {:?}:{} at {:x} written to {:x} (abs: {:x})",
                        module_path,
                        name,
                        proc_addr,
                        thunk,
                        image_base + thunk as usize,
                    );

                    Ok(proc_addr)
                }
                Import::ByOrdinal { ord: _ } => {
                    Err(anyhow!("Import by ordinal is not implemented"))
                }
            }?;

            if is_wow64 {
                image_mem.write_memory(&(import_address as u32).to_ne_bytes(), thunk)?;
            } else {
                image_mem.write_memory(&(import_address as u64).to_ne_bytes(), thunk)?;
            }

            thunk += if is_wow64 {
                mem::size_of::<u32>()
            } else {
                mem::size_of::<u64>()
            };
        }
    }

    // Initialize static TLS
    {
        let stub_data = VirtualMem::alloc(
            &process,
            0,
            mem::size_of::<LDR_DATA_TABLE_ENTRY_BASE>(),
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_READWRITE,
        )?;

        let ldr_data = LDR_DATA_TABLE_ENTRY_BASE {
            pad: [0; 0x30],
            dll_base: image_base,
        };

        let ldr_data_bytes = unsafe {
            slice::from_raw_parts(
                &ldr_data as *const LDR_DATA_TABLE_ENTRY_BASE as *const u8,
                mem::size_of::<LDR_DATA_TABLE_ENTRY_BASE>(),
            )
        };

        stub_data.write_memory(ldr_data_bytes, 0)?;

        let stub = if is_wow64 {
            create_stub_ldrphandletlsdata32(stub_data.address(), &process)
        } else {
            create_stub_ldrphandletlsdata64(stub_data.address(), &process)
        }?;

        let stub_mem = VirtualMem::alloc(
            &process,
            0,
            stub.size(),
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        stub_mem.write_memory(&stub, 0)?;

        let stub_fn = unsafe { mem::transmute::<usize, thread::StartRoutine>(stub_mem.address()) };

        let thr = Thread::spawn_remote(
            &process,
            None,
            stub_fn,
            None,
            ThreadCreationFlags::IMMEDIATE,
            None,
        )?;

        thr.wait(10000)?;

        ensure!(thr.exit_code()? == 0, "LdrpHandleTlsData thread failed");
    }

    // Set proper memory protection for image sections
    for sh in pe.section_headers() {
        let ch = sh.Characteristics;
        let read = ch & IMAGE_SCN_MEM_READ != 0;
        let write = ch & IMAGE_SCN_MEM_WRITE != 0;
        let exec = ch & IMAGE_SCN_MEM_EXECUTE != 0;

        let protect = if read && write && exec {
            ProtectFlag::PAGE_EXECUTE_READWRITE
        } else if read && exec {
            ProtectFlag::PAGE_EXECUTE_READ
        } else if read && write {
            ProtectFlag::PAGE_READWRITE
        } else if read {
            ProtectFlag::PAGE_READONLY
        } else if exec {
            ProtectFlag::PAGE_EXECUTE
        } else {
            ProtectFlag::PAGE_NOACCESS
        };

        let old_protect = image_mem.virtual_protect(
            sh.VirtualAddress as usize,
            sh.VirtualSize as usize,
            protect,
        )?;

        println!(
            "Set memory protection for {} to {:?} (was {:?})",
            sh.name().unwrap(),
            protect,
            ProtectFlag::from_bits_truncate(old_protect)
        );
    }

    // We estimate the size of the loader function + LoaderInfo struct
    // We could place a function after the loader to calculate the
    // actual size, but compiling in release mode doesn't guarantee
    // that the loader_end function is placed directly after the loader function
    let loader_size = 0x200;

    let loader_mem = VirtualMem::alloc(
        &process,
        0,
        loader_size,
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_EXECUTE_READWRITE,
    )?;

    println!(
        "Allocated loader buffer at {:x} with size {:x}",
        loader_mem.address() as usize,
        loader_mem.size(),
    );

    // Construct LoaderInfo and retrieve loader function
    let (loader_info, loader) = if is_wow64 {
        let loader_info = LoaderInfo32 {
            image_base: image_base as u32,
            entry_point: unsafe {
                mem::transmute::<usize, FnDllMain>(image_base + entry_point_offset)
            },
        };

        (Wrap::T32(loader_info), get_loader32()?)
    } else {
        let (exception_fn_table, exception_fn_count) = {
            let exception = match pe.exception()? {
                Wrap::T32(_except32) => panic!(), // This should never happen
                Wrap::T64(except64) => except64,
            };

            ensure!(
                exception.check_sorted(),
                "Exception routines are not sorted"
            );

            let exception_data_directory =
                pe.data_directory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
            let exception_fn_table = (exception_data_directory.VirtualAddress as usize + image_base)
                as PRUNTIME_FUNCTION;
            let exception_fn_count = exception.functions().count();

            (exception_fn_table, exception_fn_count)
        };

        let loader_info = LoaderInfo64 {
            image_base,
            entry_point: unsafe {
                mem::transmute::<usize, FnDllMain>(image_base + entry_point_offset)
            },
            exception_fn_table,
            exception_fn_count,
            rtl_add_function_table: unsafe {
                mem::transmute::<usize, FnRtlAddFunctionTable>(
                    Module::find_or_load_internal("kernel32.dll")?
                        .proc_address("RtlAddFunctionTable")?,
                )
            },
        };

        (Wrap::T64(loader_info), get_loader64()?)
    };

    // Write LoaderInfo to loader buffer
    let loaderinfo_bytes = match loader_info {
        Wrap::T32(loader_info) => unsafe {
            slice::from_raw_parts(
                &loader_info as *const LoaderInfo32 as *const u8,
                mem::size_of::<LoaderInfo32>(),
            )
        },
        Wrap::T64(loader_info) => unsafe {
            slice::from_raw_parts(
                &loader_info as *const LoaderInfo64 as *const u8,
                mem::size_of::<LoaderInfo64>(),
            )
        },
    };

    loader_mem.write_memory(loaderinfo_bytes, 0)?;

    // Write loader to loader buffer
    loader_mem.write_memory(&loader, loaderinfo_bytes.len())?;

    // Transmute the loader buffer into a function pointer
    let loader_mem_as_fn = unsafe {
        mem::transmute::<*const winapic_void, thread::StartRoutine>(
            (loader_mem.address() as usize + loaderinfo_bytes.len()) as *const winapic_void,
        )
    };

    println!("Loader routine at {:x}", loader_mem_as_fn as usize);

    // Spawn a thread to execute the loader buffer in the target process
    let thread = Thread::spawn_remote(
        &process,
        None,
        loader_mem_as_fn,
        Some(loader_mem.address() as *mut c_void),
        ThreadCreationFlags::IMMEDIATE,
        None,
    )?;

    thread.wait(9999999)?;

    ensure!(thread.exit_code()? == TRUE as u32);

    Ok(image_base)
}

// Loader for WoW64 (32-bit)
#[repr(C)]
struct LoaderInfo32 {
    image_base: u32,
    entry_point: FnDllMain,
}

fn get_loader32() -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x86::Assembler::new()?;
    dynasm!(assembler
        ; .arch x86
        ; push ebp
        ; mov ebp, esp

        // Put LoaderInfo32 into ecx
        ; mov ecx, [ebp + 8]

        // Push DllMain args
        ; push 0
        ; push DLL_PROCESS_ATTACH as _
        ; push DWORD [ecx]

        // Call DllMain
        ; mov eax, [ecx + 8] // Why is image_base 8 bytes large as a u32?
        ; call eax

        ; mov esp, ebp
        ; pop ebp
        ; ret
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}

// Loader for 64-bit
#[repr(C)]
struct LoaderInfo64 {
    image_base: usize,
    entry_point: FnDllMain,
    // SEH stuff
    exception_fn_table: PRUNTIME_FUNCTION,
    exception_fn_count: usize,
    rtl_add_function_table: FnRtlAddFunctionTable,
}

fn get_loader64() -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x64::Assembler::new()?;
    dynasm!(assembler
        ; .arch x64
        ; push rbp
        ; mov rbp, rsp

        // Put LoaderInfo64 struct into rsi
        ; lea rsi, [rcx]

        // Prep args for RtlAddFunctionTable
        ; mov rcx, [rsi + 16]
        ; mov rdx, [rsi + 24]
        ; mov r8, [rsi]

        // Call RtlAddFunctionTable
        ; mov rax, [rsi + 32]
        ; sub rsp, 32
        ; call rax
        ; add rsp, 32

        // Return 0 if RtlAddFunctionTable fails
        ; test rax, rax
        ; jnz ->dllmain
        ; xor rax, rax
        ; mov rsp, rbp
        ; pop rbp
        ; ret

        // Prep DllMain args and call it
        ; ->dllmain:
        ; mov rcx, [rsi]
        ; mov rdx, 1
        ; mov r8, 0
        ; mov rax, [rsi + 8]
        ; sub rsp, 32
        ; call rax
        ; add rsp, 32

        ; mov rsp, rbp
        ; pop rbp
        ; ret
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}

// Functions for retrieving LdrpHandleTlsData across architectures
// Credits to Blackbone for the signatures and offsets
const SIG_LDRPHANDLETLSDATA32: &str = "33 f6 85 c0 79 3";
const OFFSET_LDRPHANDLETLSDATA32: usize = 0x2c;

const SIG_LDRPHANDLETLSDATA64: &str = "74 33 44 8d 43 9";
const OFFSET_LDRPHANDLETLSDATA64: usize = 0x46;

fn get_ldrphandletlsdata(is_wow64: bool, process: &Process) -> anyhow::Result<usize> {
    let ntdll = if is_wow64 {
        Module::find_or_load_external(process.pid()?, Path::new("ntdll.dll"))
    } else {
        Module::find_or_load_internal("ntdll.dll")
    }?;

    let ntdll_info = ntdll.info()?;

    let data = {
        let mut buf = vec![0; ntdll_info.SizeOfImage as usize];
        process.read_memory(&mut buf, ntdll_info.lpBaseOfDll as usize)?;

        buf
    };

    let (sig, offset) = if is_wow64 {
        (SIG_LDRPHANDLETLSDATA32, OFFSET_LDRPHANDLETLSDATA32)
    } else {
        (SIG_LDRPHANDLETLSDATA64, OFFSET_LDRPHANDLETLSDATA64)
    };

    Ok(patternscan::scan(&data, sig)?
        .first()
        .ok_or_else(|| anyhow!("Failed to find function ntdll::LdrpHandleTlsData",))?
        - offset
        + ntdll_info.lpBaseOfDll as usize)
}

// The asm stub that is responsible for invoking LdrpHandleTlsData
fn create_stub_ldrphandletlsdata32(
    stub_data_address: usize,
    process: &Process,
) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x86::Assembler::new()?;
    dynasm!(assembler
        ; .arch x86
        ; push ebp
        ; mov ebp, esp
        ; mov eax, DWORD stub_data_address as _
        ; push eax
        ; mov eax, DWORD get_ldrphandletlsdata(true, process)? as _
        ; call eax
        ; mov esp, ebp
        ; pop ebp
        ; ret
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}

fn create_stub_ldrphandletlsdata64(
    stub_data_address: usize,
    process: &Process,
) -> anyhow::Result<ExecutableBuffer> {
    let mut assembler = dynasmrt::x64::Assembler::new()?;
    dynasm!(assembler
        ; .arch x64
        ; mov rax, QWORD get_ldrphandletlsdata(false, process)? as _
        ; mov rcx, QWORD stub_data_address as _
        ; call rax
        ; ret
    );

    assembler.commit()?;

    Ok(assembler.finalize().unwrap())
}
