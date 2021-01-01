pub mod injectionmethod;
pub mod injector;
pub mod loadlibrary;
pub mod manualmap;

use injectionmethod::InjectionMethod;
use injector::Injector;
use loadlibrary::LoadLibraryInjector;
use manualmap::ManualMapInjector;

#[cfg(target_arch = "x86")]
use pelite::pe32::PeFile;

#[cfg(target_arch = "x86_64")]
use pelite::pe64::PeFile;

pub fn inject(
    pid: u32,
    pe: PeFile,
    image: &[u8],
    method: InjectionMethod,
) -> Result<usize, Box<dyn std::error::Error>> {
    match method {
        InjectionMethod::LoadLibrary => LoadLibraryInjector::inject(pid, pe, image),
        InjectionMethod::ManualMap => ManualMapInjector::inject(pid, pe, image),
    }
}
