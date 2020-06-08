use std::ptr;
use winapi::um::winnt::IMAGE_FILE_HEADER;

pub struct CoffHeader {
    internal_header: IMAGE_FILE_HEADER,
}

impl CoffHeader {
    pub fn from_ptr(p: *const u8) -> Self {
        let internal_header = unsafe { ptr::read(p as *const IMAGE_FILE_HEADER) };

        Self { internal_header }
    }
}
