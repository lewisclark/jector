use winapi::um::winnt;

bitflags! {
    pub struct ProcessAccess: u32 {
        const DELETE = winnt::DELETE;
        const READ_CONTROL = winnt::READ_CONTROL;
        const SYNCHRONIZE = winnt::SYNCHRONIZE;
        const WRITE_DAC = winnt::WRITE_DAC;
        const WRITE_OWNER = winnt::WRITE_OWNER;
    }
}
