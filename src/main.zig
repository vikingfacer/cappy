const std = @import("std");
const pcap = @import("replayer_lib");

pub fn main() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var errBuff = [_]u8{0} ** 256;
    const cap: *pcap.pcap = pcap.open_live("lo", 4096, 1, 1000, &errBuff) orelse {
        try stdout.print("Error: {s} \n", .{errBuff});
        try bw.flush();
        return anyerror.GeneralFailure;
    };

    defer pcap.close(cap);

    _ = pcap.activate(cap);
    var hdr: ?*pcap.pktHeader = undefined;
    var ptr: ?*const u8 = undefined;
    while (pcap.next_ex(cap, &hdr, &ptr) >= 0) {
        try stdout.print("Hdr: {} \n", .{hdr.?.*.len});
        try bw.flush();
        var slice: []const u8 = undefined;
        slice.ptr = @ptrCast(ptr);
        slice.len = hdr.?.*.len;
        _ = pcap.sendpacket(cap, slice);
    }
}
