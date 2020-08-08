use super::injector::Injector;
use crate::error::Error;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::library::Library;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::thread::{self, Thread, TEB};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use field_offset::offset_of;
use pelite::pe64::imports::Import::{ByName, ByOrdinal};
use pelite::pe64::{Pe, PeFile};
use std::error;
use std::ffi::c_void;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_REL_BASED_DIR64,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE, PRUNTIME_FUNCTION,
};

const PTR_SIZE: usize = mem::size_of::<usize>();
const MAX_TLS_INDEX: usize = 1088;

type FnDllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnRtlAddFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION, u32, u64) -> u8;

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

        // Allocate a buffer inside target process for the image
        let mut image_mem = VirtualMem::alloc(
            &process,
            0,
            pe_size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        image_mem.set_free_on_drop(false);

        let image_base = image_mem.address();
        let image_delta = image_base.wrapping_sub(pe.optional_header().ImageBase as usize);

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
                section.Name.to_str()?,
                image_mem
                    .address()
                    .wrapping_add(section.VirtualAddress as usize),
                section.VirtualSize,
            );
        }

        // Do base relocation
        for block in pe.base_relocs()?.iter_blocks() {
            for word in block.words() {
                let typ = block.type_of(word) as u16;
                let rva = block.rva_of(word) as usize;

                if typ == IMAGE_REL_BASED_DIR64 {
                    let mut buf = [0_u8; PTR_SIZE];
                    image_mem.read_memory(&mut buf, rva)?;

                    let block = usize::from_ne_bytes(buf).wrapping_add(image_delta);
                    image_mem.write_memory(&block.to_ne_bytes(), rva)?;
                }
            }
        }

        // Resolve imports
        for descriptor in pe.imports()? {
            let module_name = descriptor.dll_name()?.to_str()?;
            let module_entry = process.module_entry_by_name(module_name)?;

            let module = match module_entry {
                Some(entry) => unsafe { Library::from_handle(entry.hModule, pid, true) },
                None => Library::load_external(pid, &module_name)?,
            };

            for (&va, import) in descriptor.iat()?.zip(descriptor.int()?) {
                let va = va as usize;
                let import = import?;

                let import_address = match import {
                    ByName { hint: _, name } => {
                        let proc_addr = module.proc_address(name.to_str()?)? as usize;

                        println!(
                            "Import {}:{} at {:x} written to va {:x} (abs: {:x})",
                            module_name,
                            name,
                            proc_addr,
                            va,
                            image_base + va,
                        );

                        Ok(proc_addr)
                    }
                    ByOrdinal { ord: _ } => Err(Error::new(
                        "Ordinal import resolution not implemented".to_string(),
                    )),
                }?;

                image_mem.write_memory(&import_address.to_ne_bytes(), va)?;
            }
        }

        // Initialize static TLS
        let tls_dir = pe.tls()?;
        let tls_dir_image = tls_dir.image();
        let tls_raw_data_size =
            (tls_dir_image.EndAddressOfRawData - tls_dir_image.StartAddressOfRawData) as usize;

        let mut tls_data_mem = VirtualMem::alloc(
            &process,
            0,
            tls_raw_data_size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_READWRITE,
        )?;

        tls_data_mem.set_free_on_drop(false);

        println!(
            "Allocated TLS buffer at {:x} with size {:X}",
            tls_data_mem.address() as usize,
            tls_data_mem.size(),
        );

        tls_data_mem.write_memory(tls_dir.raw_data()?, 0)?;

        // TODO: Make ThreadAccess more unpermissive
        let thread = match process.main_thread(
            crate::winapiwrapper::threadaccess::ThreadAccess::THREAD_ALL_ACCESS,
            false,
        )? {
            Some(thread) => Ok(thread),
            None => Err(Error::new(
                "Failed to obtain a pid owning thread handle to the target process".to_string(),
            )),
        }?;

        let teb = thread.teb()? as usize;
        let tlsp_offset = offset_of!(TEB => ThreadLocalStoragePointer).get_byte_offset();

        // Obtain the TLS pointer from TEB
        let mut tls_ptr = {
            let mut buf: [u8; PTR_SIZE] = [0; PTR_SIZE];
            process.read_memory(&mut buf, teb + tlsp_offset)?;

            usize::from_ne_bytes(buf)
        };

        // Allocate a buffer for ThreadLocalStoragePointer because it's null
        if tls_ptr == 0 {
            let mut tls_array = VirtualMem::alloc(
                &process,
                0,
                MAX_TLS_INDEX * PTR_SIZE,
                AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
                ProtectFlag::PAGE_READWRITE,
            )?;

            tls_array.set_free_on_drop(false);
            tls_ptr = tls_array.address();
            process.write_memory(&tls_ptr.to_ne_bytes(), teb + tlsp_offset)?;

            println!("Allocated a buffer for ThreadLocalStoragePointer because it was null");
        }

        println!("TLS array -> {:x}", tls_ptr);

        // Find a usable TLS index
        let tls_index = {
            let mut tls_index = usize::max_value();
            for index in 0..MAX_TLS_INDEX {
                let mut buf: [u8; PTR_SIZE] = [0; PTR_SIZE];
                process.read_memory(&mut buf, tls_ptr + (index * PTR_SIZE))?;

                if usize::from_ne_bytes(buf) == 0 {
                    tls_index = index;
                    break;
                }
            }

            if tls_index != usize::max_value() {
                Ok(tls_index)
            } else {
                Err(Error::new("Failed to obtain usable TLS index".to_string()))
            }
        }?;

        // Calculate the thread's TLS memory block location
        let tls_index_ptr = tls_ptr + (tls_index * PTR_SIZE);

        println!(
            "Injector thread TLS index -> {} which indexes to {:x}",
            tls_index, tls_index_ptr
        );

        // We must add image delta because AddressOfIndex relies on base relocation
        let address_of_index = tls_dir_image.AddressOfIndex as usize + image_delta;
        // Write TLS index to TLS directory AddressOfIndex
        process.write_memory(&tls_index.to_ne_bytes(), address_of_index)?;

        println!("AddressOfIndex -> {:x}", address_of_index);

        // Write our TLS memory chunk to the TLS pointer based on index
        process.write_memory(&tls_data_mem.address().to_ne_bytes(), tls_index_ptr)?;

        // Set up SEH for loader
        let exception = pe.exception()?;

        if !exception.check_sorted() {
            return Err(Box::new(Error::new(
                "Exception routines are not sorted".to_string(),
            )));
        }

        let exception_data_directory =
            pe.data_directory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
        let exception_fn_table =
            (exception_data_directory.VirtualAddress as usize + image_base) as PRUNTIME_FUNCTION;
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
                sh.Name,
                protect,
                ProtectFlag::from_bits_truncate(old_protect)
            );
        }

        // Allocate loader memory
        let loader_mem = VirtualMem::alloc(
            &process,
            0,
            // FIXME: Size of loader computation doesn't work in release mode
            (loader_end as usize - loader as usize) + mem::size_of::<LoaderInfo>(),
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        println!(
            "Allocated loader buffer at {:x} with size {:x}",
            loader_mem.address() as usize,
            loader_mem.size(),
        );

        // Construct LoaderInfo
        let lib_kernel32 = Library::load_internal("kernel32.dll")?;
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
        let loader_fn_bytes = unsafe {
            slice::from_raw_parts(loader as *const u8, loader_end as usize - loader as usize)
        };

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
    optional_header: pelite::pe64::image::IMAGE_OPTIONAL_HEADER,
    exception_fn_table: PRUNTIME_FUNCTION,
    exception_fn_count: u32,
    rtl_add_function_table: FnRtlAddFunctionTable,
}

unsafe extern "system" fn loader(param: *mut winapic_void) -> i32 {
    let loader_info = &*(param as *const LoaderInfo);

    // Fix SEH
    // TODO: Check ret value
    (loader_info.rtl_add_function_table)(
        loader_info.exception_fn_table,
        loader_info.exception_fn_count,
        loader_info.image_base as u64,
    );

    if loader_info.optional_header.AddressOfEntryPoint != 0 {
        let entry_point_addr =
            loader_info.image_base + loader_info.optional_header.AddressOfEntryPoint as usize;

        mem::transmute::<usize, FnDllMain>(entry_point_addr)(
            loader_info.image_base as HINSTANCE,
            DLL_PROCESS_ATTACH,
            0 as LPVOID,
        )
    } else {
        30
    }
}

extern "system" fn loader_end() {}
