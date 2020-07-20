use super::injector::Injector;
use crate::error::Error;
use pelite::pe64::PeFile;

pub struct LoadLibraryInjector {}

impl Injector for LoadLibraryInjector {
    fn inject(pid: u32, pe: PeFile, image: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        Err(Box::new(Error::new(
            "LoadLibraryInjector::inject not implemented".to_string(),
        )))
    }
}
