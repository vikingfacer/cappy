const std = @import("std");
const pcap = @import("replayer_lib");

pub fn main() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    var errBuf = [_]u8{0} ** 256;
    const cap: pcap.pcapture = pcap.open_live("lo", 4096, 1, 1000, &errBuf) orelse {
        try stdout.print("Error: {s} \n", .{errBuf});
        try bw.flush();
        return anyerror.GeneralFailure;
    };
    defer pcap.pcapture.close(cap);

    var fp = cap.compile("port 23", 0, 0);
    _ = cap.setfilter(&fp.?);

    var hdr: ?*pcap.pktHeader = undefined;
    var data: ?*const u8 = undefined;
    while (cap.next_ex(&hdr, &data) >= 0) {
        try stdout.print("Hdr: {} \n", .{hdr.?.*.len});
        try bw.flush();
        var slice: []const u8 = undefined;
        slice.ptr = @ptrCast(data);
        slice.len = hdr.?.*.len;
        _ = cap.sendpacket(slice);
    }
}

export fn pck(user: [*c]u8, pkt: [*c]const pcap.pktHeader, bytes: [*c]const u8) void {
    _ = user;
    _ = pkt;
    std.log.debug("{s} {s}\n", .{ "pck", bytes });
}
