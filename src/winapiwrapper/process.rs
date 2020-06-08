use std::ops::Drop;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::HANDLE;

pub struct Process {
    handle: HANDLE,
}

impl Process {
    pub fn from_pid(pid: u32, access: u32, inherit: bool) -> Self {
        let handle = unsafe { OpenProcess(access, inherit as i32, pid) };

        Self { handle }
    }

    pub fn close(&mut self) {
        if self.handle.is_null() {
            return;
        }

        unsafe { CloseHandle(self.handle) };

        self.handle = 0 as HANDLE;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.close();
    }
}
