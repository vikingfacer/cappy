//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

pub fn main() !void {
    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var errBuff = [_]u8{0} ** 256;
    const cap: *pcap.pcap = pcap.open_live("lo", 4096, 1, 1000, &errBuff) orelse {
        try stdout.print("Error: {s} \n", .{errBuff});
        try bw.flush();
        return anyerror.GeneralFailure;
    };
    _ = pcap.activate(cap);
    var hdr: [*c]pcap.pktHeader = undefined;
    var ptr: [*c]const u8 = undefined;
    while (pcap.next_ex(cap, //
        @as([*c][*c]pcap.pktHeader, &hdr), //
        &ptr) >= 0)
    {
        try stdout.print("Hdr: {} \n", .{hdr.?.*.len});
        try bw.flush();
    }
}

const std = @import("std");
const pcap = @import("replayer_lib");
