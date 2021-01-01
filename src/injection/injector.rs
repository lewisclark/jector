#[cfg(target_arch = "x86")]
use pelite::pe32::PeFile;

#[cfg(target_arch = "x86_64")]
use pelite::pe64::PeFile;

use std::error;

pub trait Injector {
    fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<usize, Box<dyn error::Error>>;
}
