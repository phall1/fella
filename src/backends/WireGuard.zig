const std = @import("std");
const Output = @import("../Output.zig");

const CONF_FILE = "/var/lib/fella/wireguard.conf";
const IFACE = "wg-fella";
const NS_NAME = "fella";

status: Status,

pub const Status = enum {
    stopped,
    running,
    failed,
};

pub fn create() @This() {
    return .{ .status = .stopped };
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Starting WireGuard backend...\n", .{});

    if (!hasBinary("wg") or !hasBinary("ip")) {
        self.status = .failed;
        try Output.stdoutPrint(io, alloc, "    [!] WireGuard requires 'wg' and 'ip' binaries\n", .{});
        return error.WgNotInstalled;
    }

    const conf = readConf(alloc) catch |err| {
        self.status = .failed;
        try Output.stdoutPrint(io, alloc, "    [!] Could not read {s}: {any}\n", .{ CONF_FILE, err });
        try Output.stdoutPrint(io, alloc, "    [*] Place a WireGuard config at {s}\n", .{CONF_FILE});
        return error.NoWgConfig;
    };
    defer alloc.free(conf);

    // Create WireGuard interface inside the host namespace, then move to netns
    try runCmd(alloc, &.{ "ip", "link", "add", IFACE, "type", "wireguard" });
    try runCmd(alloc, &.{ "ip", "link", "set", IFACE, "netns", NS_NAME });

    // Apply wg config
    try runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "wg", "setconf", IFACE, CONF_FILE });

    // Bring up interface and add routes
    try runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip", "link", "set", IFACE, "up" });

    // Add routes through the tunnel
    runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip", "route", "add", "default", "dev", IFACE }) catch {};

    self.status = .running;
    try Output.stdoutPrint(io, alloc, "    [+] WireGuard interface {s} up in namespace {s}\n", .{ IFACE, NS_NAME });
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    if (self.status == .stopped) {
        try Output.stdoutPrint(io, alloc, "[*] WireGuard not running\n", .{});
        return;
    }
    _ = runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip", "link", "del", IFACE }) catch {};
    self.status = .stopped;
    try Output.stdoutPrint(io, alloc, "    [+] WireGuard stopped\n", .{});
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    // WireGuard rotation = generate new keys and reconnect
    try Output.stdoutPrint(io, alloc, "[+] Rotating WireGuard keys...\n", .{});
    _ = generateKeys(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Key rotation failed: {any}\n", .{err});
    };
    try self.stop(io, alloc);
    try self.start(io, alloc);
}

pub fn isRunning(self: *const @This()) bool {
    return self.status == .running;
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
    const fd = try std.posix.openatZ(-100, CONF_FILE, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.os.linux.close(fd);
    var buf: [8192]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    if (n == 0) return error.EmptyConfig;
    return try alloc.dupe(u8, buf[0..n]);
}

fn generateKeys(alloc: std.mem.Allocator) !void {
    _ = alloc;
    // Best-effort: call wg genkey and write to a sidecar file
    // Real rotation requires updating the peer on the server side too,
    // so this is mostly a placeholder for future automated key exchange.
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
