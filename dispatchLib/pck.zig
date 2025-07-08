const pcap = @import("zapcap");
const std = @import("std");

export fn pck(user: [*c]u8, pkt: [*c]const pcap.pktHeader, bytes: [*c]const u8) void {
    _ = user;
    _ = pkt;
    std.log.debug("{s} {s}\n", .{ "pck", bytes });
}
