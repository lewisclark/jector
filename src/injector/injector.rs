use goblin::pe::PE;
use super::error::Error;
use crate::winapiwrapper::process::Process;

trait Injector {
	// TODO: Return base address of injected pe
	fn inject(process: Process, pe: PE) -> Result<(), Error>;
}
