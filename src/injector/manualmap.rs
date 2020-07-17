use crate::error::Error;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::library::Library;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::thread::{self, Thread};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use bytebuffer::{ByteBuffer, Endian};
use pelite::pe64::{Pe, PeFile};
use std::error;
use std::ffi::c_void;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPVOID};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_ORDINAL_FLAG, IMAGE_REL_BASED_DIR64, LPCSTR,
};

const BASE_RELOCATION_SIZE: usize = mem::size_of::<IMAGE_BASE_RELOCATION>();

type FnDllMain = unsafe extern "system" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnLoadLibraryA = unsafe extern "system" fn(LPCSTR) -> HMODULE;
type FnGetProcAddress = unsafe extern "system" fn(HMODULE, LPCSTR) -> FARPROC;

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

    let image_delta =
        (image_mem.address() as usize).wrapping_sub(pe.optional_header().ImageBase as usize);

    println!(
        "Allocated image buffer at {:x}",
        image_mem.address() as usize
    );

    image_mem.set_free_on_drop(false);

    // Initialize image buffer
    let mut image_buf = ByteBuffer::new();
    image_buf.resize(image_mem.size());
    image_buf.set_endian(Endian::LittleEndian);

    // Write image headers
    image_buf.write_bytes(&image[..pe.optional_header().SizeOfHeaders as usize]);

    // Write image sections
    for section in pe.section_headers() {
        let start = section.PointerToRawData as usize;
        let size = section.SizeOfRawData as usize;

        image_buf.set_wpos(section.VirtualAddress as usize);
        image_buf.write_bytes(&image[start..start + size]);

        println!(
            "Section {} written at {:x} with size {:x}",
            section.Name.to_str()?,
            image_mem.address() as usize + start,
            size
        );
    }

    // Initialize static TLS
    let tls_dir = pe.tls()?;
    let tls_dir_image = tls_dir.image();
    let tls_raw_data_size =
        (tls_dir_image.EndAddressOfRawData - tls_dir_image.StartAddressOfRawData) as usize;

    let tls_data_mem = VirtualMem::alloc(
        &process,
        0,
        tls_raw_data_size,
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_READWRITE,
    )?;

    println!(
        "Allocated TLS buffer at {:x}",
        tls_data_mem.address() as usize
    );

    let tls_raw_data = tls_dir.raw_data()?;
    tls_data_mem.write_memory(tls_raw_data, 0)?;

    let thread = match process.main_thread(
        crate::winapiwrapper::threadaccess::ThreadAccess::THREAD_ALL_ACCESS,
        false,
    )? {
        Some(thread) => Ok(thread),
        None => Err(Error::new(
            "Failed to obtain a pid owning thread handle to the target process".to_string(),
        )),
    }?;

    // We must add image delta because AddressOfIndex relies on base relocation
    let _address_of_index = tls_dir_image.AddressOfIndex as usize + image_delta;
    let _tls_index = 0;
    let _teb = thread.teb()?;

    // TODO for static TLS initialization
    // Actually compute TLS index
    // Implement a WriteProcessMemory wrapper for Process (needs refactoring with VirtualMem
    // (trait?))
    // Read teb.ThreadLocalStoragePointer if == 0 then allocate (size = ????)
    // write tls_data_mem ptr to teb.ThreadLocalStoragePointer[my tls index]

    // Write image buffer to image memory
    image_mem.write_memory(&image_buf.to_bytes(), 0)?;

    // Allocate loader memory
    let loader_mem = VirtualMem::alloc(
        &process,
        0,
        (loader_end as usize - loader as usize) + mem::size_of::<LoaderInfo>(),
        AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
        ProtectFlag::PAGE_EXECUTE_READWRITE,
    )?;

    println!(
        "Allocated loader buffer at {:x}",
        loader_mem.address() as usize
    );

    // Initialize loader buffer
    let mut loader_buf = ByteBuffer::new();
    loader_buf.resize(loader_mem.size());
    loader_buf.set_endian(Endian::LittleEndian);

    // Construct LoaderInfo
    let lib_kernel32 = Library::load("kernel32.dll")?;
    let loader_info = LoaderInfo {
        image_base: image_mem.address() as usize,
        image_delta: image_delta,
        optional_header: pe.optional_header().clone(),
        basereloc_directory: pe.data_directory()[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize],
        import_directory: pe.data_directory()[IMAGE_DIRECTORY_ENTRY_IMPORT as usize],
        load_library: unsafe {
            mem::transmute::<*const (), FnLoadLibraryA>(lib_kernel32.proc_address("LoadLibraryA")?)
        },
        get_proc_address: unsafe {
            mem::transmute::<*const (), FnGetProcAddress>(
                lib_kernel32.proc_address("GetProcAddress")?,
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

    loader_buf.write_bytes(&loaderinfo_bytes);

    // Write loader fn bytes to loader buffer
    let loader_fn_bytes = unsafe {
        slice::from_raw_parts(loader as *const u8, loader_end as usize - loader as usize)
    };

    loader_buf.write_bytes(&loader_fn_bytes);

    // Write loader buffer to loader memory
    loader_mem.write_memory(&loader_buf.to_bytes(), 0)?;

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
    load_library: FnLoadLibraryA,
    get_proc_address: FnGetProcAddress,
}

unsafe extern "system" fn loader(param: *mut winapic_void) -> i32 {
    let loader_info = mem::transmute::<*mut winapic_void, &LoaderInfo>(param);

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
                    let reloc_offset = ((*base_reloc).VirtualAddress as usize
                        + (*entry as usize & 0xfff))
                        % 9223372036854775807;
                    let reloc_location = ((loader_info.image_base + reloc_offset)
                        % 9223372036854775807)
                        as *mut usize;

                    *reloc_location =
                        (*reloc_location + loader_info.image_delta) % 9223372036854775807;
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

            let mut orig_first_thunk = ((loader_info.image_base
                + *(import_descriptor as *const u32) as usize)
                % 9223372036854775807) as *const usize;
            let mut first_thunk = ((loader_info.image_base
                + (*import_descriptor).FirstThunk as usize)
                % 9223372036854775807) as *mut usize;

            while *orig_first_thunk != 0 {
                let proc;

                if (*orig_first_thunk & IMAGE_ORDINAL_FLAG as usize) != 0 as usize {
                    proc = (loader_info.get_proc_address)(
                        module,
                        (*orig_first_thunk & 0xffff) as LPCSTR,
                    ) as usize;
                } else {
                    let import_by_name =
                        (loader_info.image_base + *orig_first_thunk) as *const IMAGE_IMPORT_BY_NAME;

                    proc = (loader_info.get_proc_address)(module, &(*import_by_name).Name as LPCSTR)
                        as usize;
                }

                if proc == 0 {
                    return 20;
                } else {
                    *first_thunk = proc;

                    orig_first_thunk =
                        (orig_first_thunk as usize + mem::size_of::<usize>()) as *const usize;
                    first_thunk = (first_thunk as usize + mem::size_of::<usize>()) as *mut usize;
                }
            }

            import_descriptor = (import_descriptor as usize
                + mem::size_of::<IMAGE_IMPORT_DESCRIPTOR>())
                as *const IMAGE_IMPORT_DESCRIPTOR;
        }
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
        30
    }
}

extern "system" fn loader_end() {}
