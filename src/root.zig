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

pub fn create(pcapFile: [:0]const u8, errorBuffer: []u8) ?*pcap {
    return PCAP_C.pcap_create(pcapFile, errorBuffer.ptr);
}

pub fn activate(p: ?*pcap) c_int {
    return PCAP_C.pcap_activate(p);
}

pub fn next_ex(p: ?*pcap, hdr: *?*pktHeader, data: *?*const u8) isize {
    return PCAP_C.pcap_next_ex(p, @alignCast(hdr), @alignCast(data));
}
pub fn sendpacket(p: ?*pcap, buf: []const u8) isize {
    return PCAP_C.pcap_sendpacket(p, buf.ptr, @intCast(buf.len));
}
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
