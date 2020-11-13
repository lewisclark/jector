use std::error;
use std::ffi::{CStr, CString};
use winapi::shared::minwindef::{BOOL, LPARAM};
use winapi::shared::windef::HWND;
use winapi::um::winnt::CHAR;
use winapi::um::winuser::{EnumWindows, GetWindowTextA, GetWindowThreadProcessId};

pub struct Window {
    handle: HWND,
}

#[repr(C)]
struct EnumWindowsState<'a> {
    window_name: &'a CStr,
    window_found: Option<Window>,
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, param: LPARAM) -> BOOL {
    let mut state = param as *mut EnumWindowsState;
    let window = Window::from_handle(hwnd);

    if window.name().as_c_str() == (*state).window_name {
        (*state).window_found = Some(window);

        0
    } else {
        1
    }
}

impl Window {
    pub unsafe fn from_handle(handle: HWND) -> Self {
        Self { handle }
    }

    pub fn find(window_name: &str) -> Result<Option<Self>, Box<dyn error::Error>> {
        let window_name = CString::new(window_name)?;

        let state = EnumWindowsState {
            window_name: window_name.as_c_str(),
            window_found: None,
        };

        unsafe {
            EnumWindows(
                Some(enum_windows_callback),
                &state as *const EnumWindowsState as isize,
            )
        };

        Ok(state.window_found)
    }

    pub fn name(&self) -> CString {
        const BUF_LEN: usize = 0x100;

        let mut buf = Vec::new();
        buf.resize(BUF_LEN, 0);

        let copied =
            unsafe { GetWindowTextA(self.handle, buf.as_mut_ptr() as *mut CHAR, BUF_LEN as i32) };

        buf.resize(copied as usize, 0);

        unsafe { CString::from_vec_unchecked(buf) }
    }

    pub fn pid(&self) -> u32 {
        let mut p = 0;

        unsafe { GetWindowThreadProcessId(self.handle, &mut p as *mut u32) };

        p
    }
}
