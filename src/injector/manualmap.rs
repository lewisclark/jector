use goblin::pe::PE;
use std::error;
use super::injector::Injector;
use crate::winapiwrapper::process::Process;
use crate::winapiwrapper::virtualmem::VirtualMem;

pub struct ManualMapInjector {

}

impl Injector for ManualMapInjector {
	fn inject(process: Process, pe: PE) -> Result<(), Box<dyn error::Error>> {
		VirtualMem::alloc(&process, 0, pe.size, 0, 0)?;

		Ok(())
	}
}
