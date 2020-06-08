use std::ptr;
use winapi::um::winnt::IMAGE_DOS_HEADER;

pub struct DosHeader {
    internal_header: IMAGE_DOS_HEADER,
}

impl DosHeader {
    pub fn from_ptr(p: *const u8) -> Self {
        let internal_header: IMAGE_DOS_HEADER = unsafe { ptr::read(p as *const IMAGE_DOS_HEADER) };

        Self { internal_header }
    }

    pub fn e_magic(&self) -> u16 {
        self.internal_header.e_magic
    }

    pub fn e_lfanew(&self) -> i32 {
        self.internal_header.e_lfanew
    }
}
