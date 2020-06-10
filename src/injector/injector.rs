use goblin::pe::PE;
use std::error;
use crate::winapiwrapper::process::Process;

pub trait Injector {
	// TODO: Return base address of injected pe
	fn inject(process: Process, pe: PE) -> Result<(), Box<dyn error::Error>>;
}
