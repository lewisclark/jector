pub mod injectionmethod;
pub mod loadlibrary;
pub mod manualmap;

use injectionmethod::InjectionMethod;

pub fn inject(
    pid: u32,
    pe: pelite::PeFile,
    image: &[u8],
    method: InjectionMethod,
) -> anyhow::Result<usize> {
    match method {
        InjectionMethod::LoadLibrary => loadlibrary::inject(pid, pe, image),
        InjectionMethod::ManualMap => manualmap::inject(pid, pe, image),
    }
}
