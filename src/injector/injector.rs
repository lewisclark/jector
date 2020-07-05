use pelite::pe64::{PeFile, Pe};
use std::error;

pub trait Injector {
    // TODO: Return base address of injected pe
    fn inject(pid: u32, pe: PeFile, image: &Vec<u8>) -> Result<(), Box<dyn error::Error>>;
}
