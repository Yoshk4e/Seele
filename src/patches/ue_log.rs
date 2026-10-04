use std::{
    fs::{File, OpenOptions},
    io::Write,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    engine::{HookTarget, JmpContext, Patch, Session},
    util,
};

pub struct UeLogPatch;

impl Patch for UeLogPatch {
    fn install(&self, session: &mut Session) {
        let base = util::get_module_base(None);
        session.attach(HookTarget::from_rva(base, 0x10D0C70), hook_ue_logf);
    }
}

#[repr(C)]
struct LogCallSite {
    fmt: *const u16,
    file: *const u8,
    line: u32,
    verbosity: u8,
}

struct VaCursor {
    r8: u64,
    r9: u64,
    stack: *const u64,
    idx: usize,
}

impl VaCursor {
    unsafe fn next(&mut self) -> u64 {
        let v = match self.idx {
            0 => self.r8,
            1 => self.r9,
            n => unsafe { *self.stack.add(n - 2) },
        };
        self.idx += 1;
        v
    }
}

static LOG_FILE: OnceLock<Mutex<File>> = OnceLock::new();

const LOG_PATH: &str = "ue_log.txt";

fn log_file() -> Option<&'static Mutex<File>> {
    Some(LOG_FILE.get_or_init(|| {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_PATH)
            .unwrap_or_else(|e| panic!("failed to open log file {LOG_PATH}: {e}"));
        Mutex::new(file)
    }))
}

fn write_log_line(line: &str) {
    let Some(lock) = log_file() else { return };
    let Ok(mut file) = lock.lock() else { return };

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let _ = writeln!(file, "[{ts}] {line}");
}

fn hook_ue_logf(ctx: &mut JmpContext) {
    let regs = ctx.regs();
    let a2 = regs.rdx as *const LogCallSite;
    if a2.is_null() {
        return;
    }

    let site = unsafe { &*a2 };
    if site.fmt.is_null() {
        return;
    }

    let mut cursor = VaCursor {
        r8: regs.r8,
        r9: regs.r9,
        stack: (regs.rsp + 0x28) as *const u64,
        idx: 0,
    };

    let fmt = unsafe { read_wstr(site.fmt) };
    let message = unsafe { format_message(&fmt, &mut cursor) };

    let line = format!("[UE_LOG] v{} {message}", site.verbosity);
    println!("{line}");
    write_log_line(&line);
}

unsafe fn read_wstr(ptr: *const u16) -> String {
    let mut len = 0usize;
    while len < 1024 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn read_cstr(ptr: *const u8) -> String {
    let mut len = 0usize;
    while len < 1024 && unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned()
}

unsafe fn format_message(fmt: &str, va: &mut VaCursor) -> String {
    let mut out = String::with_capacity(fmt.len());
    let mut chars = fmt.chars().peekable();

    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }

        let mut spec = String::new();
        let conv = loop {
            match chars.next() {
                Some(c) if "diouxXeEfFgGaAcspn%".contains(c) => break c,
                Some(c) => spec.push(c),
                None => return out,
            }
        };

        match conv {
            '%' => out.push('%'),
            'd' | 'i' => out.push_str(&(unsafe { va.next() } as i64).to_string()),
            'u' => out.push_str(&unsafe { va.next() }.to_string()),
            'x' => out.push_str(&format!("{:x}", unsafe { va.next() })),
            'X' => out.push_str(&format!("{:X}", unsafe { va.next() })),
            'c' => {
                if let Some(ch) = char::from_u32(unsafe { va.next() } as u32) {
                    out.push(ch);
                }
            }
            'p' => out.push_str(&format!("{:#x}", unsafe { va.next() })),
            'f' | 'F' | 'e' | 'E' | 'g' | 'G' | 'a' | 'A' => {
                let bits = unsafe { va.next() };
                out.push_str(&f64::from_bits(bits).to_string());
            }
            's' => {
                let ptr = unsafe { va.next() } as *const u16;
                if !ptr.is_null() {
                    out.push_str(&unsafe { read_wstr(ptr) });
                }
            }
            _ => {
                if spec.contains('h') {
                    let ptr = unsafe { va.next() } as *const u8;
                    if !ptr.is_null() {
                        out.push_str(&unsafe { read_cstr(ptr) });
                    }
                } else {
                    let _ = unsafe { va.next() };
                    out.push('?');
                }
            }
        }
    }

    out
}
