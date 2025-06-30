const std = @import("std");
const pcap = @import("zapcap");
const clap = @import("clap");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // First we specify what parameters our program can take.
    // We can use `parseParamsComptime` to parse a string into an array of `Param(Help)`.
    const params = comptime clap.parseParamsComptime(
        \\-h, --help            Display this help and exit.
        \\-l, --list            list devices to listen upon
        \\-d, --device <STR>    use specified device
        \\-p, --program <STR>   dynamically loaded program
        \\<STR>...           filter network traffic
    );

    // Declare our own parsers which are used to map the argument strings to other
    // types.
    const parsers = comptime .{
        .STR = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = gpa.allocator(),
        // The assignment separator can be configured. `--number=1` and `--number:1` is now
        // allowed.
        .assignment_separators = "=:",
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0)
        std.debug.print("--help\n", .{});
    if (res.args.list != 0) {
        try listdevices(stdout);
    }
    if (res.args.device) |d|
        std.debug.print("--device= {s}\n", .{d});
    if (res.args.program) |p|
        std.debug.print("--program= {s}\n", .{p});
    for (res.positionals[0]) |filter|
        std.debug.print("{s}\n", .{filter});
}

fn listdevices(out: anytype) !void {
    var dev: ?*pcap.pcap_if = undefined;
    var errorBuffer = [_]u8{0} ** 2048;
    if (pcap.findalldevs(&dev, &errorBuffer) == 0) {
        while (dev.?.next != null) {
            try out.print("{s: <10} ", .{dev.?.name});

            try out.print("{s}", .{"<"});
            if (dev.?.flags & pcap.IF_LOOPBACK == pcap.IF_LOOPBACK)
                try out.print("{s},", .{"LOOPBACK"});

            try out.print("{s},", .{if (dev.?.flags & pcap.IF_UP == pcap.IF_UP)
                "UP"
            else
                "DOWN"});

            if (dev.?.flags & pcap.IF_RUNNING == pcap.IF_RUNNING)
                try out.print("{s},", .{"RUNNING"});

            if (dev.?.flags & pcap.IF_WIRELESS == pcap.IF_WIRELESS)
                try out.print("{s},", .{"WIRELESS"});

            try out.print("{s}", .{switch (dev.?.flags & pcap.IF_CONNECTION_STATUS) {
                pcap.IF_CONNECTION_STATUS_UNKNOWN => "UNKNOWN",
                pcap.IF_CONNECTION_STATUS_CONNECTED => "CONNECTED",
                pcap.IF_CONNECTION_STATUS_DISCONNECTED => "DISCONNECTED",
                pcap.IF_CONNECTION_STATUS_NOT_APPLICABLE => "NOT APPLICABLE",
                else => "UNKNOWN",
            }});

            try out.print("{s}\n", .{">"});
            dev = dev.?.next;
        }
    }
}

export fn pck(user: [*c]u8, pkt: [*c]const pcap.pktHeader, bytes: [*c]const u8) void {
    _ = user;
    _ = pkt;
    std.log.debug("{s} {s}\n", .{ "pck", bytes });
}
