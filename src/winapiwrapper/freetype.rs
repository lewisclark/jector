use winapi::um::winnt;

bitflags! {
    pub struct FreeType: u32 {
        const MEM_DECOMMIT = winnt::MEM_DECOMMIT;
        const MEM_RELEASE = winnt::MEM_RELEASE;
    }
}
