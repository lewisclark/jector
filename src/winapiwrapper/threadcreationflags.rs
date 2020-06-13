use winapi::um::winbase;

bitflags! {
    pub struct ThreadCreationFlags: u32 {
        const IMMEDIATE = 0;
        const CREATE_SUSPENDED = winbase::CREATE_SUSPENDED;
    }
}
