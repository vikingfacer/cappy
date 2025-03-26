//! By convention, root.zig is the root source file when making a library. If
//! you are making an executable, the convention is to delete this file and
//! start with main.zig instead.
const std = @import("std");
const testing = std.testing;

const PCAP_C = @cImport({
    @cInclude("pcap.h");
});

pub const pcap = PCAP_C.pcap_t;
pub const pktHeader = PCAP_C.pcap_pkthdr;
pub const bfp_program = PCAP_C.bpf_program;
pub const pcapHandler = PCAP_C.pcap_handler;
pub const pcap_if = PCAP_C.pcap_if_t;

pub fn create(pcapFile: [:0]const u8, errorBuffer: []u8) ?*pcap {
    return PCAP_C.pcap_create(pcapFile, errorBuffer.ptr);
}

pub fn findalldevs(devs: *?*pcap_if, errbuf: []u8) isize {
    return PCAP_C.pcap_findalldevs(@alignCast(devs), errbuf.ptr);
}

pub fn activate(p: ?*pcap) c_int {
    return PCAP_C.pcap_activate(p);
}

pub fn compile(p: ?*pcap, fp: ?*bfp_program, str: [:0]const u8, optimize: c_int, netmask: c_uint) isize {
    return PCAP_C.pcap_compile(p, fp, str, optimize, netmask);
}

pub fn setfilter(p: ?*pcap, fp: ?*bfp_program) isize {
    return PCAP_C.pcap_setfilter(p, fp);
}
pub fn next_ex(p: ?*pcap, hdr: *?*pktHeader, data: *?*const u8) isize {
    return PCAP_C.pcap_next_ex(p, @alignCast(hdr), @alignCast(data));
}
pub fn loop(p: ?*pcap, cnt: c_int, hdlr: ?*pcapHandler, user: [:0]u8) isize {
    return PCAP_C.pcap_loop(p, cnt, hdlr, user);
}

pub fn dispatch(p: ?*pcap, cnt: c_int, hdlr: pcapHandler, user: ?[*]u8) isize {
    return PCAP_C.pcap_dispatch(p, cnt, hdlr, user);
}

pub fn sendpacket(p: ?*pcap, buf: []const u8) isize {
    return PCAP_C.pcap_sendpacket(p, buf.ptr, @intCast(buf.len));
}
//
//pcap_open_live
pub fn open_live(
    device: [:0]const u8, //
    snaplen: i32,
    promisc: i32,
    to_ms: i32,
    errorBuffer: []u8,
) ?*pcap {
    return PCAP_C.pcap_open_live(device, snaplen, promisc, to_ms, errorBuffer.ptr);
}

pub fn close(p: ?*pcap) void {
    PCAP_C.pcap_close(p);
}
