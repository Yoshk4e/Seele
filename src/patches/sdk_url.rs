use windows::Win32::System::Memory::{PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VirtualProtect};

use crate::{
    engine::{Patch, Session},
    util,
};

const SDK_BASES: &[(usize, &str)] = &[
    (0x8512A58, "https://account-master-tp.happyelements.cn/"),
    (0x8512A88, "https://account.happyelements.com/"),
    (0x8512AB0, "https://accountcn.happyelements.cn/"),
    (0x8512C30, "https://accounth5-tp.happyelements.cn/"),
    (0x8512C58, "https://heweb.happyelements.com/"),
    (0x8512C80, "https://heweb.happyelements.cn/"),
];

const HOST: &str = "127.0.0.1";
const PORT: &str = "10010";

pub struct SdkUrlPatch;

impl Patch for SdkUrlPatch {
    fn install(&self, _session: &mut Session) {
        let base = util::get_module_base(None);

        for &(rva, original) in SDK_BASES {
            let addr = base + rva;
            let current = unsafe { std::slice::from_raw_parts(addr as *const u8, original.len() + 1) };

            if &current[..original.len()] != original.as_bytes() || current[original.len()] != 0 {
                eprintln!("[seele] sdk base @ 0x{rva:X} does not match {original}, skipped");
                continue;
            }

            let local = format!("http://{HOST}:{PORT}/");
            let mut bytes = local.clone().into_bytes();
            bytes.push(0);

            if unsafe { write_protected(addr, &bytes) } {
                println!("SDK base: {original} -> {local}");
            } else {
                eprintln!("[seele] sdk base @ 0x{rva:X} could not be written");
            }
        }
    }
}

unsafe fn write_protected(addr: usize, bytes: &[u8]) -> bool {
    let mut old = PAGE_PROTECTION_FLAGS::default();

    unsafe {
        if VirtualProtect(addr as *const _, bytes.len(), PAGE_READWRITE, &mut old).is_err() {
            return false;
        }

        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
        let _ = VirtualProtect(addr as *const _, bytes.len(), old, &mut old);
    }

    true
}
