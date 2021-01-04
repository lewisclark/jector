use winapi::um::handleapi::CloseHandle;
use winapi::um::winnt::HANDLE;

pub trait HandleOwner {
    unsafe fn from_handle(handle: HANDLE) -> Self;

    fn handle(&self) -> HANDLE;

    fn is_handle_closable(&self) -> bool;

    fn close_handle(&self) -> anyhow::Result<()> {
        if !self.is_handle_closable() {
            return Ok(());
        }

        let ret = unsafe { CloseHandle(self.handle()) };

        if ret != 0 {
            Ok(())
        } else {
            Err(anyhow!(function_call_failure!("CloseHandle")))
        }
    }
}
