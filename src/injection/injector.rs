use pelite::pe64::PeFile;
use std::error;

// TODO: Return loaded image base
pub trait Injector {
    fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<(), Box<dyn error::Error>>;
}
