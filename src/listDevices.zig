const std = @import("std");
const pcap = @import("zapcap");

pub fn listdevices(out: anytype) !void {
    var dev: ?*pcap.pcap_if = undefined;
    var errorBuffer = [_]u8{0} ** 2048;
    if (pcap.findalldevs(&dev, &errorBuffer) == 0) {
        while (dev.?.next != null) {
            try out.print("{s: <10} ", .{dev.?.name});

            try out.print("{s}", .{"<"});
            if (dev.?.flags & pcap.IF_LOOPBACK == pcap.IF_LOOPBACK)
                try out.print("{s},", .{"LOOPBACK"});

            try out.print("\x1B{s}\x1B[0m,", .{if (dev.?.flags & pcap.IF_UP == pcap.IF_UP)
                "[32mUP"
            else
                "[31mDOWN"});

            if (dev.?.flags & pcap.IF_RUNNING == pcap.IF_RUNNING)
                try out.print("\x1B{s}\x1B[0m,", .{"[;42mRUNNING"});

            if (dev.?.flags & pcap.IF_WIRELESS == pcap.IF_WIRELESS)
                try out.print("\x1B{s}\x1B[0m,", .{"[35mWIRELESS"});

            try out.print("\x1B{s}\x1B[0m", .{switch (dev.?.flags & pcap.IF_CONNECTION_STATUS) {
                pcap.IF_CONNECTION_STATUS_UNKNOWN => "[34mUNKNOWN",
                pcap.IF_CONNECTION_STATUS_CONNECTED => "[32mCONNECTED",
                pcap.IF_CONNECTION_STATUS_DISCONNECTED => "[31mDISCONNECTED",
                pcap.IF_CONNECTION_STATUS_NOT_APPLICABLE => "[34mNOT APPLICABLE",
                else => "[0mUNKNOWN",
            }});

            try out.print("{s}\n", .{">"});
            dev = dev.?.next;
        }
    }
}
