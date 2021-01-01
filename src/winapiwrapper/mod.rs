pub mod alloctype;
pub mod freetype;
pub mod handleowner;
pub mod module;
pub mod process;
pub mod processaccess;
pub mod protectflag;
pub mod snapshot;
pub mod snapshotflags;
pub mod thread;
pub mod threadaccess;
pub mod threadcreationflags;
pub mod virtualmem;
pub mod window;

use winapi::um::errhandlingapi::GetLastError;

fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

#[derive(Error, Debug)]
pub enum WinApiError {
    #[error("Function call to {0} failed [GetLastError() = {}]", get_last_error())]
    FunctionCallFailure(String),
}
