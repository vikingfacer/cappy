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

pub fn next_ex(p: ?*pcap, hdr: [*c][*c]pktHeader, data: *[*c]const u8) c_int {
    return PCAP_C.pcap_next_ex(p, hdr, @alignCast(data));
}

//pcap_open_live
pub fn open_live(device: [:0]const u8, snaplen: c_int, promisc: c_int, to_ms: c_int, errorBuffer: []u8) ?*pcap {
    return PCAP_C.pcap_open_live(device, snaplen, promisc, to_ms, errorBuffer.ptr);
}

test "Create Pcap" {
    var errBuf = [_]u8{0} ** 256;
    try std.testing.expect(null != create("any", &errBuf));
}

test "Activate Pcap" {
    var errBuf = [_]u8{0} ** 256;
    const capture = create("any", &errBuf);
    try std.testing.expect(null != capture);
    try std.testing.expect(0 == activate(capture));
}
