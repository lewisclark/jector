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
use pelite::pe64::{Pe, PeFile};
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

const NUM_BASE_RELOC_BLOCKS: usize = 2048;

type FnDllMain = unsafe extern "C" fn(HINSTANCE, DWORD, LPVOID) -> BOOL;
type FnLoadLibraryA = unsafe extern "C" fn(LPCSTR) -> HMODULE;
type FnGetProcAddress = unsafe extern "C" fn(HMODULE, LPCSTR) -> FARPROC;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PeFile, image: &Vec<u8>) -> Result<(), Box<dyn error::Error>> {
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

        // Collect base relocation blocks
        let mut base_reloc_blocks = {
            let mut blocks = [BaseRelocBlock {
                ptr: 0 as *mut usize,
                typ: 0,
            }; NUM_BASE_RELOC_BLOCKS];
            let mut i = 0;

            for block in pe.base_relocs()?.iter_blocks() {
                for &word in block.words() {
                    if word != 0 {
                        blocks[i] = BaseRelocBlock {
                            ptr: (image_mem.address() as usize + block.rva_of(&word) as usize)
                                as *mut usize,
                            typ: block.type_of(&word),
                        };

                        i += 1;
                    }
                }
            }

            blocks
        };

        // Construct LoaderInfo
        let lib_kernel32 = Library::load("kernel32.dll")?;
        let loader_info = LoaderInfo {
            image_base: image_mem.address() as usize,
            image_delta: image_mem.address() as usize - pe.optional_header().ImageBase as usize,
            optional_header: pe.optional_header().clone(),
            base_reloc_blocks: base_reloc_blocks,
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
            image_mem.address() as usize + pe.optional_header().AddressOfEntryPoint as usize
        );
        println!(
            "entry point offset from base -> {:x}",
            pe.optional_header().AddressOfEntryPoint
        );
        //std::thread::sleep_ms(60000);
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

        //loop {}

        Ok(())
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BaseRelocBlock {
    ptr: *mut usize,
    typ: u8,
}

// Loader
#[repr(C)]
struct LoaderInfo {
    image_base: usize,
    image_delta: usize,
    optional_header: pelite::pe64::image::IMAGE_OPTIONAL_HEADER,
    base_reloc_blocks: [BaseRelocBlock; NUM_BASE_RELOC_BLOCKS],
    load_library: FnLoadLibraryA,
    get_proc_address: FnGetProcAddress,
}

unsafe extern "C" fn loader(param: *mut winapic_void) -> u32 {
    let loader_info = mem::transmute::<*mut winapic_void, &LoaderInfo>(param);

    {
        let mut i = 0;
        while i < NUM_BASE_RELOC_BLOCKS {
            let block = &loader_info.base_reloc_blocks[i];

            if block.ptr as usize == 0 {
                break;
            }

            *block.ptr += loader_info.image_delta;
            i += 1;
        }
    }

    0
    /*
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
    */
}

extern "C" fn loader_end() {}
