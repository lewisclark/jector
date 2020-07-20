use pelite::pe64::PeFile;
use std::error;

pub trait Injector {
    fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<usize, Box<dyn error::Error>>;
}
