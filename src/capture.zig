const std = @import("std");
const pcap = @import("zapcap");
const EtherStruct = @import("etherStruct");

pub fn printPacket(out: *std.Io.Writer, data: []const u8) !void {
    const ethHeader = std.mem.bytesToValue(EtherStruct.ethFrame, data);
    try out.print("{any}\n", .{ethHeader});
    out.flush() catch |err| std.debug.print("Error: {}\n", .{err});
    const frameType: EtherStruct.EthFrametype = @enumFromInt(ethHeader.frameType);
    switch (frameType) {
        EtherStruct.EthFrametype.IPv4 => {
            try printIp(out, data[@sizeOf(EtherStruct.ethFrame)..]);
        },
        else => {},
    }
}

fn printIp(out: *std.Io.Writer, data: []const u8) !void {
    const ipHeader = std.mem.bytesToValue(EtherStruct.ipHeader, //
        data);
    try out.print("{any}\n", .{ipHeader});
    out.flush() catch |err| std.debug.print("Error: {}\n", .{err});
    const ipProto: EtherStruct.ipProtocol = @enumFromInt(ipHeader.protocol);
    switch (ipProto) {
        EtherStruct.ipProtocol.ICMP => {
            try out.print("{any}\n", .{std.mem.bytesToValue(EtherStruct.icmpHeader, data)});
        },
        EtherStruct.ipProtocol.TCP => {
            try out.print("{any}\n", .{std.mem.bytesToValue(EtherStruct.tcpHeader, data)});
        },
        EtherStruct.ipProtocol.UDP => try out.print("{s}\n", .{"unable to print"}),
        _ => try out.print("{s}\n", .{"unable to print"}),
    }
    out.flush() catch |err| std.debug.print("Error: {}\n", .{err});
}

pub fn live(out: anytype, liveCapture: pcap.pcapture) !void {
    var header: ?*pcap.pktHeader = null;
    var data: ?[*]const u8 = null;
    while (liveCapture.next_ex(&header, &data) >= 0) {
        // skip first byte: first byte shows pcap capture device
        const packetSlice: []const u8 = data.?[1..header.?.caplen];
        try printPacket(out, packetSlice);
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
