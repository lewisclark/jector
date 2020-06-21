use super::error::Error;
use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;
use winapi::um::libloaderapi::LoadLibraryA;

pub struct Library {
	handle: HMODULE
}

impl Library {
	pub fn load_library(name: String) -> Result<Self, Error> {
		let name = match CString::new(name) {
			Ok(cstr) => Ok(cstr),
			Err(e) => Err(Error::new("Failed to construct CString from name arg".to_string()))
		}?.into_raw();

		let handle = unsafe { LoadLibraryA(name) };

		if handle.is_null() {
			Err(Error::new("LoadLibraryA returned NULL".to_string()))
		} else {
			Ok(Self { handle })
		}
	}
}
