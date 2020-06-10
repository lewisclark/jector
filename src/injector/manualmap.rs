use goblin::pe::PE;
use super::injector::Injector;
use super::error::Error;
use crate::winapiwrapper::process::Process;

pub struct ManualMapInjector {

}

impl Injector for ManualMapInjector {
	pub fn inject(process: Process, pe: PE) -> Result<(), Error> {
		Ok(())
	}
}
