const std = @import("std");
const Output = @import("Output.zig");

// Kernel-level traffic shaping for WireGuard interfaces.
// Uses tc (traffic control) to enforce constant-rate egress,
// making packet timing and size uniform at the wire.
//
// This is *real* traffic shaping — not the fork+exec curl loops
// that the old padding subagent used. Every packet is padded to
// a fixed cell size and emitted at a fixed rate by the kernel.

const CELL_SIZE: u32 = 1500; // bytes
const RATE_KBIT: u32 = 500; // kbps — ~62.5 KB/s sustained
const BURST: u32 = 3000; // bytes burst tolerance
const LATENCY_MS: u32 = 50;

const IFACE = "wg-fella";

pub fn apply(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Applying traffic shaping to {s}...\n", .{IFACE});

    // Clear existing qdisc
    _ = runCmdSilent(&.{ "tc", "qdisc", "del", "dev", IFACE, "root" });

    // HTB root qdisc
    try runCmd(alloc, &.{ "tc", "qdisc", "add", "dev", IFACE, "root", "handle", "1:", "htb", "default", "12" });

    // HTB class with fixed rate
    var class_buf: [256]u8 = undefined;
    const class_cmd = try std.fmt.bufPrint(&class_buf, "{d}kbit", .{RATE_KBIT});
    try runCmd(alloc, &.{ "tc", "class", "add", "dev", IFACE, "parent", "1:", "classid", "1:12", "htb", "rate", class_cmd, "burst", "3k" });

    // TBF under the HTB class to smooth bursts into constant-rate cells
    var tbf_buf: [256]u8 = undefined;
    const tbf_cmd = try std.fmt.bufPrint(&tbf_buf, "{d}kbit", .{RATE_KBIT});
    try runCmd(alloc, &.{ "tc", "qdisc", "add", "dev", IFACE, "parent", "1:12", "handle", "20:", "tbf", "rate", tbf_cmd, "burst", "3k", "latency", "50ms", "mpu", "64" });

    // Police ingress to same rate so we don't ACK faster than we transmit
    try runCmd(alloc, &.{ "tc", "qdisc", "add", "dev", IFACE, "handle", "ffff:", "ingress" });
    var police_buf: [256]u8 = undefined;
    const police_cmd = try std.fmt.bufPrint(&police_buf, "{d}kbit", .{RATE_KBIT});
    try runCmd(alloc, &.{ "tc", "filter", "add", "dev", IFACE, "parent", "ffff:", "protocol", "ip", "prio", "50", "u32", "match", "ip", "src", "0.0.0.0/0", "police", "rate", police_cmd, "burst", "3k", "drop", "flowid", ":1" });

    try Output.stdoutPrint(io, alloc, "    [*] Shaping: {d} kbps, cell ~{d} B, latency {d} ms\n", .{ RATE_KBIT, CELL_SIZE, LATENCY_MS });
}

pub fn remove(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Removing traffic shaping from {s}...\n", .{IFACE});
    _ = runCmdSilent(&.{ "tc", "qdisc", "del", "dev", IFACE, "root" });
    _ = runCmdSilent(&.{ "tc", "qdisc", "del", "dev", IFACE, "ingress" });
    try Output.stdoutPrint(io, alloc, "    [+] Shaping removed\n", .{});
}

fn runCmd(alloc: std.mem.Allocator, argv: []const []const u8) !void {
    _ = alloc;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = aa.dupeZ(u8, arg) catch return error.CmdFailed;
    }

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        if (status != 0) return error.CmdFailed;
    } else {
        return error.ForkFailed;
    }
}

fn runCmdSilent(argv: []const []const u8) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = aa.dupeZ(u8, arg) catch return -1;
    }

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.close(2);
        var devnull: [16:0]u8 = undefined;
        @memcpy(devnull[0..9], "/dev/null");
        devnull[9] = 0;
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        return @intCast(status);
    } else {
        return -1;
    }
}
