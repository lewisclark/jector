use super::error::Error;
use super::injector::Injector;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::virtualmem::VirtualMem;
use goblin::pe::PE;
use bytebuffer::{Endian, ByteBuffer};
use std::error;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PE) -> Result<(), Box<dyn error::Error>> {
		let hdr = pe.header;
		let doshdr = hdr.dos_header;
		let coffhdr = hdr.coff_header;
        let opthdr = match hdr.optional_header {
            Some(header) => Ok(header),
            None => Err(Box::new(Error::new("No optional header".to_string()))),
        }?;

        let pe_size = opthdr.windows_fields.size_of_image as usize;

        let process = Process::from_pid(
            pid,
            ProcessAccess::PROCESS_CREATE_THREAD
                | ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION
                | ProcessAccess::PROCESS_VM_OPERATION
                | ProcessAccess::PROCESS_VM_READ
                | ProcessAccess::PROCESS_VM_WRITE,
            false,
        )?;

        let mut mem = VirtualMem::alloc(
            &process,
            0,
            pe_size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        mem.set_free_on_drop(false);

        let mut buf = ByteBuffer::new();
		buf.resize(pe_size);
		buf.set_endian(Endian::LittleEndian);

		buf.write_bytes(&hdr.signature.to_le_bytes());

        mem.write(buf.to_bytes().as_ptr(), buf.len())?;

        Ok(())
    }
}
