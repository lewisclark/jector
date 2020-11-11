use winapi::shared::windef::HWND;

pub struct Window {
    handle: HWND,
}

impl Window {
    pub unsafe fn from_handle(handle: HWND) -> Self {
        Self { handle }
    }
}
