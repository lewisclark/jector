pub mod injectionmethod;
pub mod loadlibrary;
pub mod manualmap;

use injectionmethod::InjectionMethod;

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
        InjectionMethod::LoadLibrary => loadlibrary::inject(pid, pe, image),
        InjectionMethod::ManualMap => manualmap::inject(pid, pe, image),
    }
}
