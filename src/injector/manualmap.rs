use super::error::Error;
use super::injector::Injector;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::remotethread::{self, RemoteThread};
use crate::winapiwrapper::threadcreationflags::ThreadCreationFlags;
use crate::winapiwrapper::virtualmem::VirtualMem;
use bytebuffer::{ByteBuffer, Endian};
use goblin::pe::PE;
use std::error;
use std::mem;
use std::slice;
use winapi::ctypes::c_void as winapic_void;

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
                | ProcessAccess::PROCESS_VM_WRITE,
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
        for section in pe.sections {
            let start = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            image_buf.set_wpos(section.virtual_address as usize);
            image_buf.write_bytes(&image[start..start + size]);
        }

        // Write image buffer to image memory
        image_mem.write(image_buf.to_bytes().as_ptr(), image_buf.len())?;

        // Allocate loader memory
        let mut loader_mem = VirtualMem::alloc(
            &process,
            0,
            512,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        // Initialize loader buffer
        let mut loader_buf = ByteBuffer::new();
        loader_buf.resize(loader_mem.size());
        loader_buf.set_endian(Endian::LittleEndian);

        // Write loader fn bytes to loader buffer
        let loader_fn_bytes =
            unsafe { slice::from_raw_parts(loader as *const u8, loader_mem.size()) };

        loader_buf.write_bytes(&loader_fn_bytes);

        // Write loader buffer to loader memory
        loader_mem.write(loader_buf.to_bytes().as_ptr(), loader_buf.len())?;

        // Transmute the loader buffer into a function pointer
        let loader_mem_as_fn = unsafe {
            std::mem::transmute::<*const winapic_void, remotethread::StartRoutine>(
                loader_mem.address(),
            )
        };

        // Spawn a thread to execute the loader buffer in the target process
        let _thread = RemoteThread::new(
            &process,
            None,
            None,
            loader_mem_as_fn,
            None,
            ThreadCreationFlags::IMMEDIATE,
            None,
        )?;

        Ok(())
    }
}

// Loader
#[repr(C)]
struct LoaderInfo {}

extern "C" fn loader(_param: *mut winapi_cvoid) -> u32 {
    let mut n = 0;

    while n < 100 {
        n += 1;
    }

    n
}
