#[derive(Error, Debug)]
pub enum WinApiError {
    #[error("Function call to {0} failed [GetLastError() = 0x{1:x}]")]
    FunctionCallFailure(String, u32),
    #[error("Bad or invalid parameter {0}: {1}")]
    BadParameter(String, String),
}

macro_rules! function_call_failure {
    ($fn_name:expr) => {
        crate::winapiwrapper::error::WinApiError::FunctionCallFailure(
            $fn_name.to_string(),
            unsafe { winapi::um::errhandlingapi::GetLastError() },
        )
    };
}
