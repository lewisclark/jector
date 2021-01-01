use super::injector::Injector;
use crate::error::Error;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::module::Module;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::thread::{self, Thread};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use dynasmrt::{dynasm, DynasmApi};
use std::error;
use std::ffi::c_void;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_REL_BASED_ABSOLUTE,
    IMAGE_REL_BASED_DIR64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};

#[cfg(target_arch = "x86")]
use {
    pelite::pe32::image::IMAGE_OPTIONAL_HEADER,
    pelite::pe32::imports::Import::{ByName, ByOrdinal},
    pelite::pe32::{Pe, PeFile},
};

#[cfg(target_arch = "x86_64")]
use {
    pelite::pe64::image::IMAGE_OPTIONAL_HEADER,
    pelite::pe64::imports::Import::{ByName, ByOrdinal},
    pelite::pe64::{Pe, PeFile},
};

const PTR_SIZE: usize = mem::size_of::<usize>();

type FnDllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnRtlAddFunctionTable = unsafe extern "system" fn(*const RuntimeFunction, u32, u64) -> u8;

#[repr(C)]
struct LDR_DATA_TABLE_ENTRY_BASE {
    pad: [u8; 0x30],
    dll_base: usize,
}

// PRUNTIME_FUNCTION is not included in WinAPI for x86 arch for some reason?
// Let's create it ourself
#[repr(C)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
}

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<usize, Box<dyn error::Error>> {
        let pe_size = pe.optional_header().SizeOfImage as usize;

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

        let pref_image_base = pe.optional_header().ImageBase as usize;

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
        image_mem.write_memory(&image[..pe.optional_header().SizeOfHeaders as usize], 0)?;

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
                        IMAGE_REL_BASED_DIR64 => {
                            let mut buf = [0_u8; PTR_SIZE];
                            image_mem.read_memory(&mut buf, rva)?;

                            let p = usize::from_ne_bytes(buf).wrapping_add(image_delta);
                            image_mem.write_memory(&p.to_ne_bytes(), rva)?;

                            println!("Performed DIR64 base relocation at rva {:x}", rva);
                        }
                        IMAGE_REL_BASED_ABSOLUTE => {
                            println!("Skipping base relocation for type ABSOLUTE")
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
            let module_name = descriptor.dll_name()?.to_str()?;
            let module_entry = process.module_entry_by_name(module_name)?;

            let module = match module_entry {
                Some(entry) => unsafe { Module::from_handle(entry.hModule, pid, true) },
                None => Module::load_external(pid, &module_name)?,
            };

            let mut thunk = descriptor.image().FirstThunk as usize;
            for import in descriptor.int()? {
                let import = import?;

                let import_address = match import {
                    ByName { hint: _, name } => {
                        let proc_addr = module.proc_address(name.to_str()?)? as usize;

                        println!(
                            "Import {}:{} at {:x} written to {:x} (abs: {:x})",
                            module_name,
                            name,
                            proc_addr,
                            thunk,
                            image_base + thunk,
                        );

                        Ok(proc_addr)
                    }
                    ByOrdinal { ord: _ } => Err(Error::new(
                        "Ordinal import resolution not implemented".to_string(),
                    )),
                }?;

                image_mem.write_memory(&import_address.to_ne_bytes(), thunk)?;
                thunk += PTR_SIZE;
            }
        }

        // Initialize static TLS
        {
            let ntdll = Module::load_internal("ntdll.dll")?;
            let ntdll_info = ntdll.info()?;
            let data = unsafe {
                std::slice::from_raw_parts(
                    ntdll.handle() as *const u8,
                    ntdll_info.SizeOfImage as usize,
                )
            };

            // Credit to Blackbone for the signature and offset
            let matches = patternscan::scan(data, "74 33 44 8d 43 9")?;
            let ldrphandletlsdata = match matches.first() {
                Some(n) => Ok(n),
                None => Err(Error::new(String::from(
                    "Failed to find function ntdll::LdrpHandleTlsData",
                ))),
            }? - 0x46
                + ntdll.handle() as usize;

            let ldr_data = LDR_DATA_TABLE_ENTRY_BASE {
                pad: [0; 0x30],
                dll_base: image_base,
            };

            let stub_data = VirtualMem::alloc(
                &process,
                0,
                mem::size_of::<LDR_DATA_TABLE_ENTRY_BASE>(),
                AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
                ProtectFlag::PAGE_READWRITE,
            )?;

            let ldr_data_bytes = unsafe {
                slice::from_raw_parts(
                    &ldr_data as *const LDR_DATA_TABLE_ENTRY_BASE as *const u8,
                    mem::size_of::<LDR_DATA_TABLE_ENTRY_BASE>(),
                )
            };

            stub_data.write_memory(ldr_data_bytes, 0)?;

            let mut assembler = dynasmrt::x64::Assembler::new()?;
            dynasm!(assembler
                ; .arch x64
                ; mov rax, QWORD ldrphandletlsdata as _
                ; mov rcx, QWORD stub_data.address() as _
                ; call rax
                ; ret
            );
            assembler.commit()?;
            let stub = assembler.finalize().unwrap();

            let stub_mem = VirtualMem::alloc(
                &process,
                0,
                stub.size(),
                AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
                ProtectFlag::PAGE_EXECUTE_READWRITE,
            )?;

            stub_mem.write_memory(&stub, 0)?;

            let stub_fn =
                unsafe { mem::transmute::<usize, thread::StartRoutine>(stub_mem.address()) };

            let thr = Thread::spawn_remote(
                &process,
                None,
                stub_fn,
                None,
                ThreadCreationFlags::IMMEDIATE,
                None,
            )?;

            thr.wait(10000)?;

            if thr.exit_code()? != 0 {
                return Err(Box::new(Error::new(String::from(
                    "LdrpHandleTlsData failed",
                ))));
            }
        }

        // Set up SEH for loader
        let exception = pe.exception()?;

        if !exception.check_sorted() {
            return Err(Box::new(Error::new(
                "Exception routines are not sorted".to_string(),
            )));
        }

        let exception_data_directory =
            pe.data_directory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
        let exception_fn_table = (exception_data_directory.VirtualAddress as usize + image_base)
            as *const RuntimeFunction;
        let exception_fn_count = exception.functions().count() as u32;

        println!(
            "Exception function table -> {:x} with length {}",
            exception_fn_table as usize, exception_fn_count
        );

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

        // We estimate the size of the loader function
        // We could place a function after the loader to calculate the
        // actual size, but compiling in release mode doesn't guarantee
        // that the loader_end function is placed directly after the loader function
        let loader_size = 0x1000;

        // Allocate loader memory
        let loader_mem = VirtualMem::alloc(
            &process,
            0,
            loader_size + mem::size_of::<LoaderInfo>(),
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        println!(
            "Allocated loader buffer at {:x} with size {:x}",
            loader_mem.address() as usize,
            loader_mem.size(),
        );

        // Construct LoaderInfo
        let lib_kernel32 = Module::load_internal("kernel32.dll")?;
        let loader_info = LoaderInfo {
            image_base,
            optional_header: *pe.optional_header(),
            exception_fn_table,
            exception_fn_count,
            rtl_add_function_table: unsafe {
                mem::transmute::<*const (), FnRtlAddFunctionTable>(
                    lib_kernel32.proc_address("RtlAddFunctionTable")?,
                )
            },
        };

        // Write LoaderInfo to loader buffer
        let loaderinfo_bytes = unsafe {
            slice::from_raw_parts(
                &loader_info as *const LoaderInfo as *const u8,
                mem::size_of::<LoaderInfo>(),
            )
        };

        loader_mem.write_memory(loaderinfo_bytes, 0)?;

        // Write loader fn bytes to loader buffer
        let loader_fn_bytes = unsafe { slice::from_raw_parts(loader as *const u8, loader_size) };

        loader_mem.write_memory(loader_fn_bytes, loaderinfo_bytes.len())?;

        // Transmute the loader buffer into a function pointer
        let loader_mem_as_fn = unsafe {
            mem::transmute::<*const winapic_void, thread::StartRoutine>(
                (loader_mem.address() as usize + mem::size_of::<LoaderInfo>())
                    as *const winapic_void,
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

        thread.wait(60000)?;

        let code = thread.exit_code()?;
        println!("Remote thread exit code: {}", code);

        Ok(image_base)
    }
}

// Loader
#[repr(C)]
struct LoaderInfo {
    image_base: usize,
    optional_header: IMAGE_OPTIONAL_HEADER,
    exception_fn_table: *const RuntimeFunction,
    exception_fn_count: u32,
    rtl_add_function_table: FnRtlAddFunctionTable,
}

unsafe extern "system" fn loader(param: *mut winapic_void) -> i32 {
    let loader_info = &*(param as *const LoaderInfo);

    // Fix SEH
    let rtladdfunctableret = (loader_info.rtl_add_function_table)(
        loader_info.exception_fn_table,
        loader_info.exception_fn_count,
        loader_info.image_base as u64,
    );

    if rtladdfunctableret == 0 {
        return 10;
    }

    if loader_info.optional_header.AddressOfEntryPoint != 0 {
        let entry_point_addr =
            loader_info.image_base + loader_info.optional_header.AddressOfEntryPoint as usize;

        mem::transmute::<usize, FnDllMain>(entry_point_addr)(
            loader_info.image_base as HINSTANCE,
            DLL_PROCESS_ATTACH,
            0 as LPVOID,
        )
    } else {
        20
    }
}
