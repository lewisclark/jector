use super::injector::Injector;
use crate::winapiwrapper::alloctype::AllocType;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::protectflag::ProtectFlag;
use crate::winapiwrapper::virtualmem::VirtualMem;
use goblin::pe::PE;
use std::error;

pub struct ManualMapInjector {}

impl Injector for ManualMapInjector {
    fn inject(process: Process, pe: PE) -> Result<(), Box<dyn error::Error>> {
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
