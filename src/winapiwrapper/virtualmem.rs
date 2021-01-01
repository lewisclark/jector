use super::alloctype::AllocType;
use super::freetype::FreeType;
use super::handleowner::HandleOwner;
use super::process::Process;
use super::protectflag::ProtectFlag;
use super::WinApiError;
use std::ops::Drop;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx};

pub struct VirtualMem<'a> {
    process: &'a Process,
    address: usize,
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
    ) -> anyhow::Result<Self> {
        let mem = unsafe {
            VirtualAllocEx(
                process.handle(),
                address as LPVOID,
                size,
                alloc_type.bits(),
                protect.bits(),
            )
        };

        ensure!(
            !mem.is_null(),
            WinApiError::FunctionCallFailure("VirtualAllocEx".to_string())
        );

        Ok(Self {
            process,
            address: mem as usize,
            size,
            free_on_drop: true,
        })
    }

    pub fn free(&mut self, freetype: FreeType) -> anyhow::Result<()> {
        ensure!(
            self.address() != 0,
            "Attempted to free NULL virtual memory region"
        );

        let size = if freetype.contains(FreeType::MEM_RELEASE) {
            0
        } else {
            self.size
        };

        let ret = unsafe {
            VirtualFreeEx(
                self.process.handle(),
                self.address as LPVOID,
                size,
                freetype.bits(),
            )
        };

        ensure!(
            ret != 0,
            WinApiError::FunctionCallFailure("VirtualFreeEx".to_string())
        );

        Ok(())
    }

    pub fn set_free_on_drop(&mut self, free_on_drop: bool) {
        self.free_on_drop = free_on_drop
    }

    pub fn address(&self) -> usize {
        self.address
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn write_memory(&self, data: &[u8], offset: usize) -> anyhow::Result<usize> {
        self.process.write_memory(data, self.address + offset)
    }

    pub fn read_memory(&self, data: &mut [u8], offset: usize) -> anyhow::Result<usize> {
        self.process.read_memory(data, self.address + offset)
    }

    pub fn virtual_protect(
        &self,
        offset: usize,
        size: usize,
        protect: ProtectFlag,
    ) -> anyhow::Result<u32> {
        self.process
            .virtual_protect(self.address + offset, size, protect)
    }
}

impl Drop for VirtualMem<'_> {
    fn drop(&mut self) {
        if self.free_on_drop {
            self.free(FreeType::MEM_RELEASE).unwrap();
        }
    }
}
