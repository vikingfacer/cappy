const std = @import("std");
const pcap = @import("zapcap");
const clap = @import("clap");
const listdev = @import("listDevices.zig");
const runner = @import("capture.zig");

pub fn main() !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const cappyArgs =
        \\-h, --help            Display this help and exit.
        \\-l, --list            List devices to listen upon
        \\-p, --program <STR>   Dynamically loaded program
        \\-d, --device <STR>    Use specified device
        \\-i, --input <STR>     Pcap File
        \\-o, --output <STR>    output Pcap File
        \\<STR>...
    ;
    const params = comptime clap.parseParamsComptime(cappyArgs);

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
        try diag.reportToFile(.stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        std.debug.print("{s}\n", .{cappyArgs});
    } else if (res.args.list != 0) {
        try listdev.listdevices(stdout);
    } else {
        const device: []const u8 = res.args.device orelse "any";

        var errorBuffer = [_]u8{0} ** 2048;
        var capture: pcap.pcapture = undefined;
        if (res.args.input) |file| {
            if (pcap.open_offline(file, &errorBuffer)) |fileOpen| {
                capture = fileOpen;
            } else {
                std.debug.print("Unable to open file: {s}\n", .{file});
                std.debug.print("{s}\n", .{errorBuffer});
            }
        } else {
            if (pcap.open_live(device, 4096, 1, 1000, &errorBuffer)) |liveOpen| {
                capture = liveOpen;
            } else {
                std.debug.print("Unable to open device program requires root access\n", .{});
                std.debug.print("{s}\n", .{errorBuffer});
            }
        }
        defer capture.close();

        const filter = std.mem.joinZ(gpa.allocator(), " ", res.positionals[0]) catch "";
        defer gpa.allocator().free(filter);
        if (filter.len > 0) {
            if (capture.compile(filter, 0, 0)) |f| {
                var nonConstf = f;
                _ = capture.setfilter(&nonConstf);
            } else {
                std.debug.print("Unable to set filter {s}", .{filter});
            }
        }

        try runner.live(stdout, capture);
    }
}
