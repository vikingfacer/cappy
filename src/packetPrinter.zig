const std = @import("std");
const pcap = @import("zapcap");
const EtherStruct = @import("etherStruct");

fn printPacket(out: *std.Io.Writer, data: []const u8) !void {
    const T = EtherStruct.ethernet;
    const ethernetLayer = EtherStruct.toNativeValue(T, //
        data[0..EtherStruct.packedSize(T)]);
    _ = try out.write("{");
    const ft: EtherStruct.ethernetType = @enumFromInt(ethernetLayer.frameType);
    try out.print("\"{s}\" : ", .{@tagName(ft)});
    var serializer: std.json.Stringify = .{
        .writer = out,
        .options = .{ .whitespace = .indent_2 },
    };

    try serializer.write(ethernetLayer);
    switch (ft) {
        EtherStruct.ethernetType.IPv4 => {
            try printIp(out, data[EtherStruct.packedSize(T)..]);
        },
        else => {},
    }
    _ = try out.write("}\n");

    out.flush() catch |err| std.debug.print("Error: {}\n", .{err});
}

fn printIp(out: *std.Io.Writer, data: []const u8) !void {
    const ipHeader = EtherStruct.toNativeValue(EtherStruct.ipHeader, //
        data);
    const ipProto: EtherStruct.ipProtocol = @enumFromInt(ipHeader.protocol);

    try out.print(" \"{s}\" : ", .{@tagName(ipProto)});
    var serializer: std.json.Stringify = .{
        .writer = out,
        .options = .{ .whitespace = .indent_2 },
    };
    try serializer.write(ipHeader);
    serializer = .{
        .writer = out,
        .options = .{ .whitespace = .indent_2 },
    };
    switch (ipProto) {
        EtherStruct.ipProtocol.ICMP => {
            //            try out.write(std.mem.bytesToValue(EtherStruct.icmpHeader, data));
        },
        EtherStruct.ipProtocol.TCP => {
            try serializer.write(EtherStruct.toNativeValue(EtherStruct.tcpHeader, data));
        },
        EtherStruct.ipProtocol.UDP => {
            try serializer.write(EtherStruct.toNativeValue(EtherStruct.udpHeader, data));
        },
        _ => {},
    }
    out.flush() catch |err| std.debug.print("Error: {}\n", .{err});
}

pub export fn callback(user: [*c]u8, pkt: [*c]const pcap.pktHeader, bytes: [*c]const u8) void {
    _ = user;
    const packetSlice: []const u8 = bytes[2..pkt.*.caplen];
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    stdout.flush() catch |err| std.debug.print("Error: {}\n", .{err});
    printPacket(stdout, packetSlice) catch |err| std.debug.print("Error: {}\n", .{err});
}
