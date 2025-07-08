const std = @import("std");
const pcap = @import("zapcap");
const clap = @import("clap");
const listdev = @import("listDevices.zig");
const capture = @import("capture.zig");

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

    std.debug.print("device: {s}\n", .{device});
    var errorBuffer = [_]u8{0} ** 2048;
    const cap = pcap.open_live(device, 4096, 1, 1000, &errorBuffer).?;
    defer cap.close();

    const file: [:0]const u8 = try gpa.allocator().dupeZ(u8, res.args.file orelse "");
    defer gpa.allocator().free(file);

    if (res.args.program != 0) {
        const libraryName =
            try gpa.allocator().dupeZ(u8, res.positionals[0][0]);
        defer gpa.allocator().free(libraryName);
        const programName =
            try gpa.allocator().dupeZ(u8, res.positionals[0][1]);
        defer gpa.allocator().free(programName);
        try capture.dispatcher(cap, libraryName, programName);
    } else if (res.args.file != null) {} else {
        const filter = try std.mem.joinZ(gpa.allocator(), ",", res.positionals[0]);
        defer gpa.allocator().free(file);
        try capture.live(stdout, cap, filter);
    }
}
