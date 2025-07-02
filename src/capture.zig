const std = @import("std");
const pcap = @import("zapcap");

pub fn live(out: anytype, device: [:0]const u8, filter: [:0]const u8) !void {
    var errorBuffer = [_]u8{0} ** 2048;
    if (pcap.open_live(device, 4096, 1, 1000, &errorBuffer)) |liveCapture| {
        defer liveCapture.close();
        var compiled_filter: pcap.bfp_program = undefined;
        if (liveCapture.compile(filter, 0, 0)) |f| {
            compiled_filter = f;
            _ = liveCapture.setfilter(&compiled_filter);
            var header: ?*pcap.pktHeader = null;
            var data: ?[*]const u8 = null;
            while (liveCapture.next_ex(&header, &data) >= 0) {
                for (0..header.?.caplen) |i| {
                    if (i % 16 == 0) {
                        try out.print("\n{x:0>8} ", .{i});
                    }
                    try out.print("{x:02}", .{data.?[i]});
                    if ((i + 1) % 2 == 0) {
                        try out.print(" ", .{});
                    }
                }
            }
        }
    } else {
        try out.print("{s}\n", .{"Could not open device"});
    }
}
