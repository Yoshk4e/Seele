use crate::{
    engine::{HookTarget, JmpContext, Patch, Session},
    util,
};

const SET_URL_RVA: usize = 0x17E6170;
const FSTRING_ASSIGN_RVA: usize = 0x10103B0;

#[repr(C)]
struct FString {
    data: *const u16,
    num: i32,
    max: i32,
}

type FStringAssign = unsafe extern "C" fn(dst: *mut FString, src: *const FString) -> *mut FString;

pub struct HttpPatch;

impl Patch for HttpPatch {
    fn install(&self, session: &mut Session) {
        let base = util::get_module_base(None);
        session.attach(HookTarget::from_rva(base, SET_URL_RVA), hook_curl_set_url);
    }
}

fn hook_curl_set_url(ctx: &mut JmpContext) {
    const CUSTOM_URL_PREFIX: &str = "http://127.0.0.1:10010";

    let f_string = ctx.regs().rdx as *mut FString;

    let url = unsafe {
        let length = (*f_string).num - 1;
        let slice = std::slice::from_raw_parts((*f_string).data, length.max(0) as usize);
        String::from_utf16_lossy(slice)
    };

    println!("FCurlHttpRequest::SetURL: {url}");

    let mut new_url = String::from(CUSTOM_URL_PREFIX);
    url.split('/').skip(3).for_each(|s| {
        new_url.push('/');
        new_url.push_str(s);
    });

    let buf = new_url.encode_utf16().chain([0]).collect::<Vec<_>>();
    let src = FString {
        data: buf.as_ptr(),
        num: buf.len() as i32,
        max: buf.len() as i32,
    };

    unsafe {
        let assign: FStringAssign = std::mem::transmute(util::get_module_base(None) + FSTRING_ASSIGN_RVA);
        assign(f_string, &src);
    }
}
