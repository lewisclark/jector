use winapi::um::tlhelp32;

bitflags! {
    pub struct SnapshotFlags: u32 {
        const TH32CS_INHERIT = tlhelp32::TH32CS_INHERIT;
        const TH32CS_SNAPALL = tlhelp32::TH32CS_SNAPALL;
        const TH32CS_SNAPHEAPLIST = tlhelp32::TH32CS_SNAPHEAPLIST;
        const TH32CS_SNAPMODULE = tlhelp32::TH32CS_SNAPMODULE;
        const TH32CS_SNAPMODULE32 = tlhelp32::TH32CS_SNAPMODULE32;
        const TH32CS_SNAPPROCESS = tlhelp32::TH32CS_SNAPPROCESS;
        const TH32CS_SNAPTHREAD = tlhelp32::TH32CS_SNAPTHREAD;
    }
}
