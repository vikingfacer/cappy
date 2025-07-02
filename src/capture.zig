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
            var data: ?*const u8 = null;
            while (liveCapture.next_ex(&header, &data) >= 0) {
                try out.print("{*}\n", .{data});
            }
        }
    } else {
        try out.print("{s}\n", .{"Could not open device"});
    }
}
