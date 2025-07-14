const std = @import("std");
const pcap = @import("zapcap");

pub fn live(out: anytype, liveCapture: pcap.pcapture) !void {
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

pub fn dispatcher(disCapture: pcap.pcapture, library: []const u8, function: []const u8) !void {
    var buffer: [1000]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const lib: [:0]const u8 = try fba.allocator().dupeZ(u8, library);
    defer fba.allocator().free(lib);
    const fun: [:0]const u8 = try fba.allocator().dupeZ(u8, function);
    defer fba.allocator().free(fun);

    // need to dupZ these []u8 parameters
    var dlib = try std.DynLib.open(lib);

    const dispatch_fn: pcap.pcapHandler = dlib.lookup(pcap.pcapHandler, fun).?;
    while (true) {
        _ = disCapture.dispatch(0, dispatch_fn, null);
    }
}
