use std::ffi::c_void;

pub struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void, // TODO: Create struct for SECURITY_DESCRIPTOR
    inherit_handle: bool,
}
