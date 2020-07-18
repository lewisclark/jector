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
use pelite::pe64::{Pe, PeFile};
use std::error;
use std::ffi::c_void;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPVOID};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION,
    IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG, IMAGE_REL_BASED_DIR64,
    LPCSTR, PRUNTIME_FUNCTION,
};

const PTR_SIZE: usize = mem::size_of::<usize>();
const MAX_TLS_INDEX: usize = 1088;
const BASE_RELOCATION_SIZE: usize = mem::size_of::<IMAGE_BASE_RELOCATION>();

type FnDllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
type FnGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;
type FnRtlAddFunctionTable = unsafe extern "system" fn(PRUNTIME_FUNCTION, u32, u64) -> u8;

pub fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<(), Box<dyn error::Error>> {
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

    let image_delta =
        (image_mem.address() as usize).wrapping_sub(pe.optional_header().ImageBase as usize);

    println!(
        "Allocated image buffer at {:x} with size {:x}",
        image_mem.address() as usize,
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

    let exception_data_directory = pe.data_directory()[IMAGE_DIRECTORY_ENTRY_EXCEPTION as usize];
    let exception_fn_table = (exception_data_directory.VirtualAddress as usize
        + image_mem.address()) as PRUNTIME_FUNCTION;
    let exception_fn_count = exception.functions().count() as u32;

    println!(
        "Exception function table -> {:x} with length {}",
        exception_fn_table as usize, exception_fn_count
    );

    // Allocate loader memory
    let loader_mem = VirtualMem::alloc(
        &process,
        0,
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
    let lib_kernel32 = Library::load("kernel32.dll")?;
    let loader_info = LoaderInfo {
        image_base: image_mem.address() as usize,
        image_delta,
        optional_header: *pe.optional_header(),
        basereloc_directory: pe.data_directory()[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize],
        import_directory: pe.data_directory()[IMAGE_DIRECTORY_ENTRY_IMPORT as usize],
        exception_fn_table,
        exception_fn_count,
        load_library: unsafe {
            mem::transmute::<*const (), FnLoadLibraryA>(lib_kernel32.proc_address("LoadLibraryA")?)
        },
        get_proc_address: unsafe {
            mem::transmute::<*const (), FnGetProcAddress>(
                lib_kernel32.proc_address("GetProcAddress")?,
            )
        },
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
            (loader_mem.address() as usize + mem::size_of::<LoaderInfo>()) as *const winapic_void,
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

    Ok(())
}

// Loader
#[repr(C)]
struct LoaderInfo {
    image_base: usize,
    image_delta: usize,
    optional_header: pelite::pe64::image::IMAGE_OPTIONAL_HEADER,
    basereloc_directory: pelite::image::IMAGE_DATA_DIRECTORY,
    import_directory: pelite::image::IMAGE_DATA_DIRECTORY,
    exception_fn_table: PRUNTIME_FUNCTION,
    exception_fn_count: u32,
    load_library: FnLoadLibraryA,
    get_proc_address: FnGetProcAddress,
    rtl_add_function_table: FnRtlAddFunctionTable,
}

unsafe extern "system" fn loader(param: *mut winapic_void) -> i32 {
    let loader_info = &*(param as *const LoaderInfo);

    if loader_info.image_delta != 0 {
        let mut base_reloc = (loader_info.image_base
            + loader_info.basereloc_directory.VirtualAddress as usize)
            as *const IMAGE_BASE_RELOCATION;

        while (*base_reloc).VirtualAddress != 0 {
            let block_size = (*base_reloc).SizeOfBlock as usize;
            let entries_len = (block_size - BASE_RELOCATION_SIZE) / mem::size_of::<u16>();
            let mut entry_index = 0;
            let mut entry = (base_reloc as usize + BASE_RELOCATION_SIZE) as *const u16;
            while entry_index < entries_len {
                let reloc_type = *entry >> 12;
                if reloc_type == IMAGE_REL_BASED_DIR64 {
                    let reloc_offset = (*base_reloc).VirtualAddress as usize
                        + (*entry as usize & 0xfff);
                    let reloc_location = (loader_info.image_base + reloc_offset)
                        as *mut usize;

                    *reloc_location += loader_info.image_delta;
                }

                entry_index += 1;
                entry = (entry as usize + mem::size_of::<u16>()) as *const u16;
            }

            base_reloc = (base_reloc as usize + block_size) as *const IMAGE_BASE_RELOCATION;
        }
    }

    {
        let mut import_descriptor = (loader_info.image_base
            + loader_info.import_directory.VirtualAddress as usize)
            as *const IMAGE_IMPORT_DESCRIPTOR;

        while (*import_descriptor).Name != 0 {
            let module = (loader_info.load_library)(
                (loader_info.image_base + (*import_descriptor).Name as usize) as LPCSTR,
            );

            if module as usize == 0 {
                return 10;
            }

            let mut orig_first_thunk = (loader_info.image_base
                + *(import_descriptor as *const u32) as usize) as *const usize;
            let mut first_thunk = (loader_info.image_base
                + (*import_descriptor).FirstThunk as usize)
                as *mut usize;

            while *orig_first_thunk != 0 {
                let proc = if (*orig_first_thunk & IMAGE_ORDINAL_FLAG as usize) != 0 as usize {
                    (loader_info.get_proc_address)(module, (*orig_first_thunk & 0xffff) as LPCSTR)
                } else {
                    let import_by_name =
                        (loader_info.image_base + *orig_first_thunk) as *const IMAGE_IMPORT_BY_NAME;

                    (loader_info.get_proc_address)(module, &(*import_by_name).Name as LPCSTR)
                } as usize;

                if proc == 0 {
                    return 20;
                } else {
                    *first_thunk = proc;

                    orig_first_thunk = (orig_first_thunk as usize + PTR_SIZE) as *const usize;
                    first_thunk = (first_thunk as usize + PTR_SIZE) as *mut usize;
                }
            }

            import_descriptor = (import_descriptor as usize
                + mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>())
                as *const IMAGE_IMPORT_DESCRIPTOR;
        }
    }

    // Fix SEH
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
