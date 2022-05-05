#![no_std]
#![no_main]

use aya_bpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_comm},
    macros::{tracepoint, map},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use core::convert::TryInto;
use example_socket_watcher_common::SocketLog;

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<SocketLog> = PerfEventArray::<SocketLog>::with_max_entries(1024, 0);

#[tracepoint(name="example_socket_watcher")]
pub fn example_socket_watcher(ctx: TracePointContext) -> u32 {
    match unsafe { try_example_socket_watcher(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_example_socket_watcher(ctx: TracePointContext) -> Result<u32, u32> {
    // name: sys_enter_socket
    // ID: 1439
    // format:
	// field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	// field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	// field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	// field:int common_pid;	offset:4;	size:4;	signed:1;
    //
	// field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	// field:int family;	offset:16;	size:8;	signed:0;
	// field:int type;	offset:24;	size:8;	signed:0;
	// field:int protocol;	offset:32;	size:8;	signed:0;
    //
    // print fmt: "family: 0x%08lx, type: 0x%08lx, protocol: 0x%08lx", ((unsigned long)(REC->family)), ((unsigned long)(REC->type)), ((unsigned long)(REC->protocol))

    let family:u64 = ctx.read_at(16).unwrap();
    let AF_INET = 2;
    let AF_INET6 = 10;
    let AF_NETLINK = 16;
    if family != AF_NETLINK {
        return Ok(0)
    }

    let pid:u32 = (bpf_get_current_pid_tgid() >> 32).try_into().unwrap();
    let tid:u32 = bpf_get_current_pid_tgid() as u32;
    let typ:u64 = ctx.read_at(24).unwrap();
    let proto:u64 = ctx.read_at(32).unwrap();
    let comm = bpf_get_current_comm().unwrap();

    let log_entry = SocketLog {
        pid: pid,
        tid: tid,
        family: family as u32,
        typ: typ as u32,
        proto: proto as u32,
        comm: comm
    };

    EVENTS.output(&ctx, &log_entry, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
