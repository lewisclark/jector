pub mod handleowner;
pub mod module;
pub mod process;
pub mod snapshot;
pub mod thread;
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
