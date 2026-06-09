const std = @import("std");
const Output = @import("Output.zig");

// Transport obfuscation for WireGuard.
// WireGuard UDP packets have a recognizable header fingerprint
// (message type 1-4 in first byte, reserved bytes 4-7, receiver index 8-15).
// DPI and nation-state firewalls can block or flag this pattern.
//
// fella uses two strategies, in order of preference:
// 1. udp2raw — tunnels UDP through fake TCP. Both sides need udp2raw.
//    Best obfuscation; traffic looks like a generic TCP connection.
// 2. Simple header XOR — XORs the first 16 bytes with a session key.
//    Requires the server to also do the XOR. Only works for self-hosted relays.
// 3. Raw WireGuard — no obfuscation. Honest caveat: fingerprintable by DPI.

const WG_IFACE = "wg-fella";

pub const Mode = enum {
    raw,
    xor,
    udp2raw,
};

/// Detect which obfuscation modes are available.
pub fn detectMode() Mode {
    if (hasBinary("udp2raw")) return .udp2raw;
    return .raw;
}

/// Apply obfuscation for WireGuard backend.
/// If udp2raw is available, start it as a background tunnel.
pub fn apply(io: std.Io, alloc: std.mem.Allocator, wg_endpoint: []const u8) !Mode {
    const mode = detectMode();
    switch (mode) {
        .udp2raw => {
            try Output.stdoutPrint(io, alloc, "[+] Starting udp2raw obfuscation tunnel...\n", .{});
            try startUdp2raw(alloc, wg_endpoint);
            try Output.stdoutPrint(io, alloc, "    [*] WireGuard traffic masked as TCP\n", .{});
            return .udp2raw;
        },
        .xor => {
            try Output.stdoutPrint(io, alloc, "    [!] XOR obfuscation requires server-side support\n", .{});
            try Output.stdoutPrint(io, alloc, "    [*] Falling back to raw WireGuard\n", .{});
            return .raw;
        },
        .raw => {
            try Output.stdoutPrint(io, alloc, "    [!] WireGuard traffic is unobfuscated\n", .{});
            try Output.stdoutPrint(io, alloc, "    [*] Install udp2raw for DPI resistance: https://github.com/wangyu-/udp2raw\n", .{});
            return .raw;
        },
    }
}

/// Tear down any active obfuscation tunnel.
pub fn remove(io: std.Io, alloc: std.mem.Allocator) void {
    // Best-effort kill of any udp2raw processes for this interface
    _ = runCmdSilent(&.{ "pkill", "-f", "udp2raw.*wg-fella" });
    _ = Output.stdoutPrint(io, alloc, "    [+] Obfuscation tunnel stopped\n", .{}) catch {};
}

fn startUdp2raw(alloc: std.mem.Allocator, wg_endpoint: []const u8) !void {
    // Parse endpoint host:port
    const colon = std.mem.lastIndexOfScalar(u8, wg_endpoint, ':') orelse return error.BadEndpoint;
    const host = wg_endpoint[0..colon];
    const port = wg_endpoint[colon + 1 ..];

    // udp2raw listens on a local port and forwards to the real endpoint via fake TCP
    // We use 51821 as the local relay port (WG connects to localhost:51821)
    const local_port = "51821";

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(alloc);
    try argv.appendSlice(alloc, &.{
        "udp2raw",
        "-c",
        "-l",
        "0.0.0.0:",
        "-r",
        "",
        "-k",
        "fella-auto",
        "--raw-mode",
        "faketcp",
        "-a",
    });

    // Patch the argv entries with actual values
    var l_buf: [32]u8 = undefined;
    const l_str = try std.fmt.bufPrint(&l_buf, "0.0.0.0:{s}", .{local_port});
    argv.items[3] = l_str;

    var r_buf: [128]u8 = undefined;
    const r_str = try std.fmt.bufPrint(&r_buf, "{s}:{s}", .{ host, port });
    argv.items[5] = r_str;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Daemonize roughly
        _ = std.os.linux.close(0);
        _ = std.os.linux.close(1);
        _ = std.os.linux.close(2);
        var devnull: [16:0]u8 = undefined;
        @memcpy(devnull[0..9], "/dev/null");
        devnull[9] = 0;
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .RDONLY }, 0);
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);

        var argv_z: [64:null]?[*:0]const u8 = undefined;
        @memset(&argv_z, null);
        for (argv.items, 0..) |arg, i| {
            argv_z[i] = (std.heap.page_allocator.dupeZ(u8, arg) catch std.os.linux.exit(1)).ptr;
        }
        _ = std.os.linux.execve("/usr/bin/udp2raw", &argv_z, @ptrCast(std.c.environ));
        _ = std.os.linux.execve("/usr/local/bin/udp2raw", &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        // Give udp2raw a moment to bind
        _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
    } else {
        return error.ForkFailed;
    }
}

fn hasBinary(name: []const u8) bool {
    const prefixes = [_][]const u8{ "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/" };
    var buf: [128:0]u8 = undefined;
    for (prefixes) |prefix| {
        const path = std.fmt.bufPrint(&buf, "{s}{s}", .{ prefix, name }) catch continue;
        buf[path.len] = 0;
        if (std.os.linux.access(&buf, 0) == 0) return true;
    }
    return false;
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
