const std = @import("std");
const pcap = @import("zapcap");
const clap = @import("clap");
const listdev = @import("listDevices.zig");
const runner = @import("capture.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // First we specify what parameters our program can take.
    // We can use `parseParamsComptime` to parse a string into an array of `Param(Help)`.
    const params = comptime clap.parseParamsComptime(
        \\-h, --help            Display this help and exit.
        \\-l, --list            List devices to listen upon
        \\-p, --program <STR>   Dynamically loaded program
        \\-d, --device <STR>    Use specified device
        \\-i, --input <STR>     Pcap File
        \\-o, --output <STR>    output Pcap File
        \\<STR>...
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

    const device: []const u8 = res.args.device orelse "any";

    var errorBuffer = [_]u8{0} ** 2048;
    var capture: pcap.pcapture = undefined;
    if (res.args.input) |file| {
        if (pcap.create(file, &errorBuffer)) |fileOpen| {
            capture = fileOpen;
        } else {
            try stdout.print("Unable to open file: {s}\n", .{file});
            try stdout.print("{s}\n", .{errorBuffer});
        }
    } else {
        if (pcap.open_live(device, 4096, 1, 1000, &errorBuffer)) |liveOpen| {
            capture = liveOpen;
        } else {
            try stdout.print("Unable to open device program requires root access\n", .{});
            try stdout.print("{s}\n", .{errorBuffer});
        }
    }
    defer capture.close();

    const filter = std.mem.joinZ(gpa.allocator(), " ", res.positionals[0]) catch "";
    defer gpa.allocator().free(filter);
    if (capture.compile(filter, 0, 0)) |f| {
        var nonConstf = f;
        _ = capture.setfilter(&nonConstf);
    } else {
        try stdout.print("Unable to set filter {s}", .{filter});
    }

    if (res.args.program) |program| {
        var seq = std.mem.splitSequence(u8, program, ":");
        try stdout.print("{?s} {?s}", .{ seq.first(), seq.next() });
        const lib = seq.first();
        const fun = seq.next().?;
        try runner.dispatcher(capture, lib, fun);
    } else {
        try runner.live(stdout, capture);
    }
}
