use super::error::Error;
use super::injector::Injector;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::virtualmem::VirtualMem;
use bytebuffer::{ByteBuffer, Endian};
use goblin::pe::PE;
use std::error;
use std::mem;
use std::slice;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PE, image: &Vec<u8>) -> Result<(), Box<dyn error::Error>> {
        let hdr = pe.header;
        let doshdr = hdr.dos_header;
        let coffhdr = hdr.coff_header;
        let opthdr = match hdr.optional_header {
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

        let mut image_buf = ByteBuffer::new();
        image_buf.resize(pe_size);
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
            pe_size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        // Initialize loader buffer
        let mut loader_buf = ByteBuffer::new();
        loader_buf.resize(8092);
        loader_buf.set_endian(Endian::LittleEndian);

        // Write loader fn to loader buffer
        let loader_fn_ptr =
            unsafe { slice::from_raw_parts(loader as *const u8, mem::size_of::<usize>()) };

        loader_buf.write_bytes(&loader_fn_ptr);

        // Write loader buffer to loader memory
        loader_mem.write(loader_buf.to_bytes().as_ptr(), loader_buf.len())?;

        Ok(())
    }
}

// Loader

struct LoaderInfo {}

#[no_mangle]
extern "system" fn loader() {
    println!("hi");
}
