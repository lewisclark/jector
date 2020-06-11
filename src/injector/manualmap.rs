use super::injector::Injector;
use super::error::Error;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::processaccess::ProcessAccess;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::virtualmem::VirtualMem;
use goblin::pe::PE;
use std::error;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(pid: u32, pe: PE) -> Result<(), Box<dyn error::Error>> {
		let opthdr = match pe.header.optional_header {
			Some(header) => Ok(header),
			None => Err(Box::new(Error::new("No optional header".to_string())))
		}?;

        let process = Process::from_pid(
			pid,
			ProcessAccess::PROCESS_CREATE_THREAD
				| ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION
				| ProcessAccess::PROCESS_VM_OPERATION,
            false,
        )?;

        let mut mem = VirtualMem::alloc(
            &process,
            0,
            opthdr.windows_fields.size_of_image as usize,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

		mem.set_free_on_drop(false);

        Ok(())
    }
}
