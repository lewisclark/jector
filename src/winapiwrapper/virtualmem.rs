use super::alloctype::AllocType;
use super::error::Error;
use super::freetype::FreeType;
use super::process::Process;
use super::protectflag::ProtectFlag;
use std::ffi::c_void;
use std::ops::Drop;
use std::ptr;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx};

pub struct VirtualMem<'a> {
    process: &'a Process,
    address: *mut c_void,
    size: usize,
    free_on_drop: bool,
}

impl<'a> VirtualMem<'a> {
    pub fn alloc(
        process: &'a Process,
        address: usize,
        size: usize,
        alloc_type: AllocType,
        protect: ProtectFlag,
    ) -> Result<Self, Error> {
        let mem = unsafe {
            VirtualAllocEx(
                process.handle()?,
                address as LPVOID,
                size,
                alloc_type.bits(),
                protect.bits(),
            )
        };

        if mem.is_null() {
            Err(Error::new("VirtualAllocEx returned NULL".to_string()))
        } else {
            Ok(Self {
                process: process,
                address: mem as *mut c_void,
                size: size,
                free_on_drop: true,
            })
        }
    }

    pub fn free(&mut self, freetype: FreeType) -> Result<(), Error> {
        if self.address.is_null() {
            return Err(Error::new(
                "Tried to free null virtual memory region".to_string(),
            ));
        }

        let size = if freetype.contains(FreeType::MEM_RELEASE) {
            0
        } else {
            self.size
        };

        let ret = unsafe {
            VirtualFreeEx(
                self.process.handle()?,
                self.address as LPVOID,
                size,
                freetype.bits(),
            )
        };

        if ret == 0 {
            Err(Error::new("VirtualFreeEx failed".to_string()))
        } else {
            Ok(())
        }
    }

    pub fn set_free_on_drop(&mut self, free_on_drop: bool) {
        self.free_on_drop = free_on_drop
    }

    pub fn free_on_drop(&self) -> bool {
        self.free_on_drop
    }

    pub fn write(&mut self, src: *const c_void, size: usize) -> Result<(), Error> {
        if size > self.size {
            return Err(Error::new(
                "Arg size is greater than buffer size".to_string(),
            ));
        }

        if src.is_null() || self.address.is_null() {
            return Err(Error::new("Src or buffer is null".to_string()));
        }

        unsafe { ptr::copy(src, self.address, size) }

        Ok(())
    }
}

impl Drop for VirtualMem<'_> {
    fn drop(&mut self) {
        if self.free_on_drop {
            self.free(FreeType::MEM_RELEASE).unwrap();
        }
    }
}
