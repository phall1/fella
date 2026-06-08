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
    runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip", "route", "add", "default", "dev", IFACE }) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not add default route in netns: {any}\n", .{err});
    };

    self.status = .running;
    try Output.stdoutPrint(io, alloc, "    [+] WireGuard interface {s} up in namespace {s}\n", .{ IFACE, NS_NAME });
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    if (self.status == .stopped) {
        try Output.stdoutPrint(io, alloc, "[*] WireGuard not running\n", .{});
        return;
    }
    _ = runCmd(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip", "link", "del", IFACE }) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not delete wg interface: {any}\n", .{err});
    };
    self.status = .stopped;
    try Output.stdoutPrint(io, alloc, "    [+] WireGuard stopped\n", .{});
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating WireGuard interface...\n", .{});
    generateKeys(alloc, io) catch |err| {
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

fn generateKeys(alloc: std.mem.Allocator, io: std.Io) !void {
    // Generate new WireGuard keypair and update the config file.
    // Note: the server peer must also be updated with the new public key
    // for this to result in a working tunnel.
    const priv = try runCmdOutput(alloc, &.{ "wg", "genkey" });
    defer alloc.free(priv);
    const trimmed_priv = std.mem.trim(u8, priv, " \n\r\t");
    if (trimmed_priv.len == 0) return error.KeyGenFailed;

    var pubkey_argv: std.ArrayList([]const u8) = .empty;
    defer pubkey_argv.deinit(alloc);
    try pubkey_argv.appendSlice(alloc, &.{ "wg", "pubkey" });
    const pubkey = try runCmdOutputWithStdin(alloc, pubkey_argv.items, trimmed_priv);
    defer alloc.free(pubkey);
    const trimmed_pub = std.mem.trim(u8, pubkey, " \n\r\t");
    if (trimmed_pub.len == 0) return error.KeyGenFailed;

    // Update PrivateKey in config
    const conf = readConf(alloc) catch return;
    defer alloc.free(conf);
    const new_conf = try replacePrivateKey(alloc, conf, trimmed_priv);
    defer alloc.free(new_conf);

    const fd = try std.posix.openatZ(-100, CONF_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, new_conf.ptr, new_conf.len);

    // Save public key sidecar for user reference
    const pub_fd = try std.posix.openatZ(-100, "/var/lib/fella/wireguard.pub", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(pub_fd);
    _ = std.os.linux.write(pub_fd, trimmed_pub.ptr, trimmed_pub.len);
    _ = std.os.linux.write(pub_fd, "\n", 1);

    try Output.stdoutPrint(io, alloc, "    [*] New pubkey saved to /var/lib/fella/wireguard.pub\n", .{});
    try Output.stdoutPrint(io, alloc, "    [*] Update the peer on your server with this pubkey\n", .{});
}

fn replacePrivateKey(alloc: std.mem.Allocator, conf: []const u8, new_key: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var it = std.mem.splitScalar(u8, conf, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "PrivateKey")) {
            try out.appendSlice(alloc, "PrivateKey = ");
            try out.appendSlice(alloc, new_key);
            try out.append(alloc, '\n');
        } else {
            try out.appendSlice(alloc, line);
            try out.append(alloc, '\n');
        }
    }
    return out.toOwnedSlice(alloc);
}

fn runCmdOutput(alloc: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    return runCmdOutputWithStdin(alloc, argv, "");
}

fn runCmdOutputWithStdin(alloc: std.mem.Allocator, argv: []const []const u8, stdin_data: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = aa.dupeZ(u8, arg) catch return error.CmdFailed;
    }

    const tmp_out = "/tmp/fella_wg_out";
    const tmp_in = "/tmp/fella_wg_in";
    _ = std.os.linux.unlink(tmp_out);
    _ = std.os.linux.unlink(tmp_in);

    if (stdin_data.len > 0) {
        var in_z: [256:0]u8 = undefined;
        @memcpy(in_z[0..tmp_in.len], tmp_in);
        in_z[tmp_in.len] = 0;
        const in_fd = std.os.linux.open(&in_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        if (in_fd >= 0) {
            _ = std.os.linux.write(@intCast(in_fd), stdin_data.ptr, stdin_data.len);
            _ = std.os.linux.close(@intCast(in_fd));
        }
    }

    const pid = std.os.linux.fork();
    if (pid == 0) {
        if (stdin_data.len > 0) {
            var in_z: [256:0]u8 = undefined;
            @memcpy(in_z[0..tmp_in.len], tmp_in);
            in_z[tmp_in.len] = 0;
            const in_fd = std.os.linux.open(&in_z, .{ .ACCMODE = .RDONLY }, 0);
            if (in_fd >= 0) _ = std.os.linux.dup2(@intCast(in_fd), 0);
        }
        var out_z: [256:0]u8 = undefined;
        @memcpy(out_z[0..tmp_out.len], tmp_out);
        out_z[tmp_out.len] = 0;
        const out_fd = std.os.linux.open(&out_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        if (out_fd >= 0) {
            _ = std.os.linux.dup2(@intCast(out_fd), 1);
            _ = std.os.linux.dup2(@intCast(out_fd), 2);
            _ = std.os.linux.close(@intCast(out_fd));
        }
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        if (status != 0) return error.CmdFailed;

        var out_z: [256:0]u8 = undefined;
        @memcpy(out_z[0..tmp_out.len], tmp_out);
        out_z[tmp_out.len] = 0;
        const fd = std.posix.openatZ(-100, &out_z, .{ .ACCMODE = .RDONLY }, 0) catch return error.CmdFailed;
        defer _ = std.os.linux.close(fd);
        var buf: [4096]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch return error.CmdFailed;
        return alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \n\r")) catch error.CmdFailed;
    } else {
        return error.ForkFailed;
    }
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
