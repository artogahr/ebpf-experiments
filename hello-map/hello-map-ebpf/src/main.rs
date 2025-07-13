#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    helpers::bpf_get_current_uid_gid,
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[map(name = "COUNTER_TABLE")]
static mut COUNTER_TABLE: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn hello_map(ctx: TracePointContext) -> u32 {
    match try_hello_map(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_hello_map(_ctx: TracePointContext) -> Result<u32, u32> {
    unsafe {
        let uid = bpf_get_current_uid_gid() as u32;
        let p = COUNTER_TABLE.get_ptr(&uid);
        match p {
            Some(counter) => {
                let _ = COUNTER_TABLE.insert(&uid, &(*counter + 1), 0);
            }
            None => {
                let _ = COUNTER_TABLE.insert(&uid, &0, 0);
            }
        }
    }
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
