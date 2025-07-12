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

// pcap if constant flags
pub const IF_LOOPBACK = PCAP_C.PCAP_IF_LOOPBACK;
pub const IF_UP = PCAP_C.PCAP_IF_UP;
pub const IF_RUNNING = PCAP_C.PCAP_IF_RUNNING;
pub const IF_WIRELESS = PCAP_C.PCAP_IF_WIRELESS;
pub const IF_CONNECTION_STATUS = PCAP_C.PCAP_IF_CONNECTION_STATUS;
pub const IF_CONNECTION_STATUS_UNKNOWN = PCAP_C.PCAP_IF_CONNECTION_STATUS_UNKNOWN;
pub const IF_CONNECTION_STATUS_CONNECTED = PCAP_C.PCAP_IF_CONNECTION_STATUS_CONNECTED;
pub const IF_CONNECTION_STATUS_DISCONNECTED = PCAP_C.PCAP_IF_CONNECTION_STATUS_DISCONNECTED;
pub const IF_CONNECTION_STATUS_NOT_APPLICABLE = PCAP_C.PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE;

pub fn create(pcapFile: []const u8, errorBuffer: []u8) ?pcapture {
    if (PCAP_C.pcap_create(pcapFile, errorBuffer.ptr)) |p| {
        return pcapture{
            .cap = p,
        };
    } else {
        return null;
    }
}

//pcap_open_live
pub fn open_live(
    device: []const u8, //
    snaplen: i32,
    promisc: i32,
    to_ms: i32,
    errorBuffer: []u8,
) ?pcapture {
    if (PCAP_C.pcap_open_live(device, snaplen, promisc, to_ms, errorBuffer.ptr)) |p| {
        return pcapture{
            .cap = p,
        };
    } else {
        return null;
    }
}

pub fn findalldevs(devs: *?*pcap_if, errbuf: []u8) isize {
    return PCAP_C.pcap_findalldevs(@alignCast(devs), errbuf.ptr);
}

pub const pcapture = struct {
    cap: *pcap,
    const Self = @This();

    pub fn activate(self: Self) bool {
        return 0 != PCAP_C.pcap_activate(self.cap);
    }

    pub fn compile(
        self: Self, //
        str: [:0]const u8, //
        optimize: c_int, //
        netmask: c_uint,
    ) ?bfp_program {
        var fp: bfp_program = undefined;
        if (0 == PCAP_C.pcap_compile(self.cap, &fp, str, optimize, netmask)) {
            return fp;
        } else {
            return null;
        }
    }

    pub fn setfilter(self: Self, fp: *bfp_program) isize {
        return PCAP_C.pcap_setfilter(self.cap, fp);
    }

    pub fn next_ex(self: Self, hdr: *?*pktHeader, data: *?[*]const u8) isize {
        return PCAP_C.pcap_next_ex(self.cap, @alignCast(hdr), @alignCast(data));
    }

    pub fn loop(self: Self, cnt: c_int, hdlr: ?*pcapHandler, user: [:0]u8) isize {
        return PCAP_C.pcap_loop(self.cap, cnt, hdlr, user);
    }

    pub fn dispatch(self: Self, cnt: c_int, hdlr: pcapHandler, user: ?[*]u8) isize {
        return PCAP_C.pcap_dispatch(self.cap, cnt, hdlr, user);
    }

    pub fn sendpacket(self: Self, buf: []const u8) isize {
        return PCAP_C.pcap_sendpacket(self.cap, buf.ptr, @intCast(buf.len));
    }

    pub fn inject(self: Self, buf: []const u8) isize {
        return PCAP_C.pcap_inject(self.cap, buf.ptr, @intCast(buf.len));
    }

    pub fn close(self: Self) void {
        PCAP_C.pcap_close(self.cap);
    }
};
