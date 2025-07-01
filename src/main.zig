const std = @import("std");
const pcap = @import("zapcap");
const clap = @import("clap");
const listdev = @import("listDevices.zig");

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
        \\-f, --filter <STR>     filter network traffic
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
        try listdev.listdevices(stdout);
    }

    const device: [:0]const u8 =
        try gpa.allocator().dupeZ(u8, res.args.device orelse "any");
    defer gpa.allocator().free(device);
    errdefer gpa.allocator().free(device);

    const filter: [:0]const u8 = try gpa.allocator().dupeZ(u8, res.args.filter orelse "");
    defer gpa.allocator().free(filter);
    errdefer gpa.allocator().free(filter);

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
                try stdout.print("{*}\n", .{data});
            }
        }
    } else {
        try stdout.print("{s}\n", .{"Could not open device"});
    }
}

export fn pck(user: [*c]u8, pkt: [*c]const pcap.pktHeader, bytes: [*c]const u8) void {
    _ = user;
    _ = pkt;
    std.log.debug("{s} {s}\n", .{ "pck", bytes });
}
