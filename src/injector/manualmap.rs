use super::injector::Injector;
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
		let process = Process::from_pid(pid, ProcessAccess::PROCESS_CREATE_THREAD | ProcessAccess::PROCESS_QUERY_LIMITED_INFORMATION | ProcessAccess::PROCESS_VM_OPERATION, false)?;

        VirtualMem::alloc(
            &process,
            0,
            pe.size,
            AllocType::MEM_COMMIT | AllocType::MEM_RESERVE,
            ProtectFlag::PAGE_EXECUTE_READWRITE,
        )?;

        Ok(())
    }
}
