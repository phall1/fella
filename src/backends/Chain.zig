const std = @import("std");
const Output = @import("../Output.zig");
const Tor = @import("Tor.zig");

const WG_IFACE = "wg-fella";
const WG_CONF = "/var/lib/fella/wireguard.conf";

status: Status,
tor: Tor,

pub const Status = enum {
    stopped,
    running,
    failed,
};

pub fn create() @This() {
    return .{ .status = .stopped, .tor = Tor.create() };
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Starting chained backend (WireGuard -> Tor)...\n", .{});

    if (!hasBinary("wg") or !hasBinary("ip")) {
        self.status = .failed;
        try Output.stdoutPrint(io, alloc, "    [!] Chain requires 'wg' and 'ip' binaries\n", .{});
        return error.WgNotInstalled;
    }

    // Verify WireGuard config exists
    const conf = readConf(alloc) catch |err| {
        self.status = .failed;
        try Output.stdoutPrint(io, alloc, "    [!] Could not read {s}: {any}\n", .{ WG_CONF, err });
        try Output.stdoutPrint(io, alloc, "    [*] Place a WireGuard config at {s}\n", .{WG_CONF});
        return error.NoWgConfig;
    };
    defer alloc.free(conf);

    // Tear down any stale interface
    _ = runCmdSilent(&.{ "ip", "link", "del", WG_IFACE });

    // Create WireGuard interface in the HOST namespace (underlay)
    try runCmd(alloc, &.{ "ip", "link", "add", WG_IFACE, "type", "wireguard" });
    try runCmd(alloc, &.{ "wg", "setconf", WG_IFACE, WG_CONF });
    try runCmd(alloc, &.{ "ip", "link", "set", WG_IFACE, "up" });

    // Extract the Address from the WireGuard config to use as OutboundBindAddress
    const wg_addr = extractAddress(conf) orelse "0.0.0.0";
    try Output.stdoutPrint(io, alloc, "    [*] WireGuard underlay up ({s})\n", .{wg_addr});

    // Add a host route so Tor's outbound traffic prefers the tunnel.
    // We route default through the WG interface if AllowedIPs is 0.0.0.0/0.
    if (hasAllowedIPs0(conf)) {
        runCmd(alloc, &.{ "ip", "route", "add", "default", "dev", WG_IFACE }) catch {
            try Output.stdoutPrint(io, alloc, "    [!] Could not set default route through {s}\n", .{WG_IFACE});
        };
    }

    // Start Tor with OutboundBindAddress pinned to the WG IP
    try self.tor.startChained(io, alloc, wg_addr);

    self.status = .running;
    try Output.stdoutPrint(io, alloc, "    [+] Chain active: netns -> torsocks -> Tor -> WireGuard\n", .{});
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    if (self.status == .stopped) {
        try Output.stdoutPrint(io, alloc, "[*] Chain not running\n", .{});
        return;
    }
    try self.tor.stop(io, alloc);
    _ = runCmdSilent(&.{ "ip", "route", "del", "default", "dev", WG_IFACE });
    _ = runCmdSilent(&.{ "ip", "link", "del", WG_IFACE });
    self.status = .stopped;
    try Output.stdoutPrint(io, alloc, "    [+] Chain stopped\n", .{});
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating chain credentials...\n", .{});
    try self.tor.rotate(io, alloc);
}

pub fn isRunning(self: *const @This()) bool {
    return self.status == .running and self.tor.isRunning();
}

fn hasBinary(name: []const u8) bool {
    const prefixes = [_][]const u8{ "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/" };
    var buf: [128:0]u8 = undefined;
    for (prefixes) |prefix| {
        const path = std.fmt.bufPrint(&buf, "{s}{s}", .{ prefix, name }) catch continue;
        buf[path.len] = 0;
        if (std.os.linux.access(&buf, 1) == 0) return true;
    }
    return false;
}

fn readConf(alloc: std.mem.Allocator) ![]u8 {
    const fd = try std.posix.openatZ(-100, WG_CONF, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.os.linux.close(fd);
    var buf: [8192]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    if (n == 0) return error.EmptyConfig;
    return try alloc.dupe(u8, buf[0..n]);
}

fn extractAddress(conf: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, conf, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "Address")) {
            const kv = std.mem.splitScalar(u8, trimmed, '=');
            var kv_it = kv;
            _ = kv_it.next();
            if (kv_it.next()) |val| {
                const v = std.mem.trim(u8, val, " \t");
                // Take first IP if CIDR
                const end = std.mem.indexOfAny(u8, v, "/,") orelse v.len;
                return v[0..end];
            }
        }
    }
    return null;
}

fn hasAllowedIPs0(conf: []const u8) bool {
    return std.mem.indexOf(u8, conf, "AllowedIPs = 0.0.0.0/0") != null or
        std.mem.indexOf(u8, conf, "AllowedIPs=0.0.0.0/0") != null;
}

fn runCmd(_alloc: std.mem.Allocator, argv: []const []const u8) !void {
    _ = _alloc;
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
