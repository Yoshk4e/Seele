use std::ffi::CString;

use windows::{Win32::System::LibraryLoader::GetModuleHandleA, core::PSTR};

pub fn get_module_base(name: Option<&str>) -> usize {
    let handle = name
        .map(|n| CString::new(n).expect("invalid module name"))
        .map(|n| PSTR::from_raw(n.as_ptr() as *mut _));

    unsafe {
        GetModuleHandleA(handle.unwrap_or(PSTR::null()))
            .expect("failed to get module base")
            .0 as usize
    }
}
