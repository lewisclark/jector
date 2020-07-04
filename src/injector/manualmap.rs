use super::error::Error;
use super::injector::Injector;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::library::Library;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::remotethread::{self, RemoteThread};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use bytebuffer::{ByteBuffer, Endian};
use goblin::pe::PE;
use std::error;
use std::ffi::c_void;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;
use winapi::shared::minwindef::{BOOL, DWORD, FARPROC, HINSTANCE, HMODULE, LPVOID};
use winapi::um::winnt::{
    DLL_PROCESS_ATTACH, IMAGE_BASE_RELOCATION, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DOS_HEADER, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_HEADERS, IMAGE_ORDINAL_FLAG, LPCSTR,
};

const BASE_RELOCATION_SIZE: usize = mem::size_of::<IMAGE_BASE_RELOCATION>();

type FnDllMain = unsafe extern "C" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnLoadLibraryA = unsafe extern "C" fn(LPCSTR) -> HMODULE;
type FnGetProcAddress = unsafe extern "C" fn(HMODULE, LPCSTR) -> FARPROC;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PE, image: &Vec<u8>) -> Result<(), Box<dyn error::Error>> {
        let opthdr = match pe.header.optional_header {
            Some(header) => Ok(header),
            None => Err(Box::new(Error::new("No optional header".to_string()))),
        }?;

        let pe_size = opthdr.windows_fields.size_of_image as usize;

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

        // Initialize image buffer
        let mut image_buf = ByteBuffer::new();
        image_buf.resize(image_mem.size());
        image_buf.set_endian(Endian::LittleEndian);

        // Write image headers
        image_buf.write_bytes(&image[..opthdr.windows_fields.size_of_headers as usize]);

        // Write image sections
        for section in &pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            image_buf.set_wpos(section.virtual_address as usize);
            image_buf.write_bytes(&image[start..start + size]);
        }

        // Do base relocation
        for section in &pe.sections {
            println!("section {:?}", section);

            for reloc in section.relocations(&image)? {
                println!("{}", reloc.virtual_address);
            }
        }

        // Write image buffer to image memory
        image_mem.write(image_buf.to_bytes().as_ptr(), image_buf.len())?;

        // Allocate loader memory
        let mut loader_mem = VirtualMem::alloc(
            &process,
            0,
            (loader_end as usize - loader as usize) + mem::size_of::<LoaderInfo>(),
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        // Initialize loader buffer
        let mut loader_buf = ByteBuffer::new();
        loader_buf.resize(loader_mem.size());
        loader_buf.set_endian(Endian::LittleEndian);

        // Construct LoaderInfo
        let lib_kernel32 = Library::load("kernel32.dll")?;
        let loader_info = LoaderInfo {
            image_base: image_mem.address() as usize,
            load_library: unsafe {
                mem::transmute::<*const (), FnLoadLibraryA>(
                    lib_kernel32.proc_address("LoadLibraryA")?,
                )
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
        loader_mem.write(loader_buf.to_bytes().as_ptr(), loader_buf.len())?;

        // Transmute the loader buffer into a function pointer
        let loader_mem_as_fn = unsafe {
            mem::transmute::<*const winapic_void, remotethread::StartRoutine>(
                (loader_mem.address() as usize + mem::size_of::<LoaderInfo>())
                    as *const winapic_void,
            )
        };

        println!("pid -> {:x}", pid);
        println!("image_mem -> {:x}", image_mem.address() as usize);
        println!("loader_mem -> {:x}", loader_mem.address() as usize);
        println!(
            "entry point -> {:x}",
            image_mem.address() as usize + pe.entry
        );
        println!("entry point offset from base -> {:x}", pe.entry);
        std::thread::sleep_ms(60000);
        println!("calling entrypoint...");

        // Spawn a thread to execute the loader buffer in the target process
        let thread = RemoteThread::new(
            &process,
            None,
            None,
            loader_mem_as_fn,
            Some(loader_mem.address() as *mut c_void),
            ThreadCreationFlags::IMMEDIATE,
            None,
        )?;

        thread.wait(10000)?;

        loop {}

        Ok(())
    }
}

// Loader
#[repr(C)]
struct LoaderInfo {
    image_base: usize,
    load_library: FnLoadLibraryA,
    get_proc_address: FnGetProcAddress,
}

unsafe extern "C" fn loader(param: *mut winapic_void) -> u32 {
    let loader_info = mem::transmute::<*mut winapic_void, &LoaderInfo>(param);
    let dos_header = mem::transmute::<usize, &IMAGE_DOS_HEADER>(loader_info.image_base);
    let nt_header = mem::transmute::<usize, &IMAGE_NT_HEADERS>(
        loader_info.image_base + dos_header.e_lfanew as usize,
    );

    let mut import_descriptor = (loader_info.image_base
        + nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress as usize)
        as *const IMAGE_IMPORT_DESCRIPTOR;

    while *(import_descriptor as *const u32) != 0 {
        let module = (loader_info.load_library)(
            (loader_info.image_base + (*import_descriptor).Name as usize) as LPCSTR,
        );

        if module as usize == 0 {
            return 1;
        }

        let mut orig_first_thunk =
            (loader_info.image_base + *(import_descriptor as *const u32) as usize) as *const usize;
        let mut first_thunk =
            (loader_info.image_base + (*import_descriptor).FirstThunk as usize) as *mut usize;

        while *orig_first_thunk != 0 {
            let mut proc = 0;

            if ((*orig_first_thunk) as usize & IMAGE_ORDINAL_FLAG as usize) != 0 {
                proc =
                    (loader_info.get_proc_address)(module, (*orig_first_thunk & 0xffff) as LPCSTR)
                        as usize;
            } else {
                let import_by_name = (loader_info.image_base + (*orig_first_thunk) as usize)
                    as *const IMAGE_IMPORT_BY_NAME;

                proc = (loader_info.get_proc_address)(module, &(*import_by_name).Name as LPCSTR)
                    as usize;
            }

            if proc == 0 {
                return 1;
            } else {
                *first_thunk = proc;

                orig_first_thunk =
                    (orig_first_thunk as usize + mem::size_of::<usize>()) as *const usize;
                first_thunk = (first_thunk as usize + mem::size_of::<usize>()) as *mut usize;
            }
        }

        import_descriptor = (import_descriptor as usize + mem::size_of::<usize>())
            as *const IMAGE_IMPORT_DESCRIPTOR;
    }

    if nt_header.OptionalHeader.AddressOfEntryPoint != 0 {
        let entry = mem::transmute::<usize, FnDllMain>(
            loader_info.image_base + nt_header.OptionalHeader.AddressOfEntryPoint as usize,
        );

        entry(
            loader_info.image_base as HINSTANCE,
            DLL_PROCESS_ATTACH,
            0 as LPVOID,
        ) as u32
    } else {
        1
    }
}

extern "C" fn loader_end() {}
