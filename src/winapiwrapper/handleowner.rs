use winapi::um::winnt::HANDLE;

pub trait HandleOwner {
    unsafe fn from_handle(handle: HANDLE) -> Self;
    fn handle(&self) -> HANDLE;
}
