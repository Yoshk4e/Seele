#![feature(unboxed_closures, default_field_values, trait_alias)]

pub mod engine;
pub mod patches;
pub mod util;

use engine::Session;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};

fn patcher() {
    unsafe { Console::AllocConsole().unwrap_unchecked() };

    let mut session = Session::new("seele");
    session.install(patches::http::HttpPatch);
    session.install(patches::ue_log::UeLogPatch);
    session.install(patches::sdk_url::SdkUrlPatch);
    session.persist();
}

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        patcher();
    }

    true
}
