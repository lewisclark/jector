use goblin::pe::PE;
use std::error;

pub trait Injector {
    // TODO: Return base address of injected pe
    fn inject(pid: u32, pe: PE) -> Result<(), Box<dyn error::Error>>;
}
