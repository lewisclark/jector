use super::error::WinApiError;
use super::handleowner::HandleOwner;
use super::process::Process;
use std::ops::Drop;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualAllocEx, VirtualFreeEx};
use winapi::um::winnt;

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

        ensure!(!mem.is_null(), function_call_failure!("VirtualAllocEx"));

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
            WinApiError::BadParameter("self.address".to_string(), "null pointer".to_string())
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

        ensure!(ret != 0, function_call_failure!("VirtualFreeEx"),);

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

// AllocType flags
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
bitflags! {
    pub struct AllocType: u32 {
        const MEM_COMMIT = winnt::MEM_COMMIT;
        const MEM_RESERVE = winnt::MEM_RESERVE;
        const MEM_RESET = winnt::MEM_RESET;
        const MEM_RESET_UNDO = winnt::MEM_RESET_UNDO;
    }
}

// FreeType flags
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
bitflags! {
    pub struct FreeType: u32 {
        const MEM_DECOMMIT = winnt::MEM_DECOMMIT;
        const MEM_RELEASE = winnt::MEM_RELEASE;
    }
}

// Memory protection flags
// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
bitflags! {
    pub struct ProtectFlag: u32 {
        const PAGE_EXECUTE = winnt::PAGE_EXECUTE;
        const PAGE_EXECUTE_READ = winnt::PAGE_EXECUTE_READ;
        const PAGE_EXECUTE_READWRITE = winnt::PAGE_EXECUTE_READWRITE;
        const PAGE_EXECUTE_WRITECOPY = winnt::PAGE_EXECUTE_WRITECOPY;
        const PAGE_NOACCESS = winnt::PAGE_NOACCESS;
        const PAGE_READONLY = winnt::PAGE_READONLY;
        const PAGE_READWRITE = winnt::PAGE_READWRITE;
        const PAGE_WRITECOPY = winnt::PAGE_WRITECOPY;
        const PAGE_TARGETS_INVALID = winnt::PAGE_TARGETS_INVALID;
        const PAGE_TARGETS_NO_UPDATE = winnt::PAGE_TARGETS_NO_UPDATE;
        const PAGE_GUARD = winnt::PAGE_GUARD;
        const PAGE_NOCACHE = winnt::PAGE_NOCACHE;
        const PAGE_WRITECOMBINE = winnt::PAGE_WRITECOMBINE;
        const PAGE_ENCLAVE_THREAD_CONTROL = winnt::PAGE_ENCLAVE_THREAD_CONTROL;
        const PAGE_ENCLAVE_UNVALIDATED = winnt::PAGE_ENCLAVE_UNVALIDATED;
    }
}
