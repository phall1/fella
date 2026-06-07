const std = @import("std");
const Output = @import("../Output.zig");
const Transport = @import("../Transport.zig");

const TORRC_TEMPLATE =
    \\SOCKSPort 127.0.0.1:9050
    \\SOCKSPort 10.200.200.1:9050
    \\DNSPort 127.0.0.1:5353
    \\DNSPort 10.200.200.1:5353
    \\ControlPort 127.0.0.1:9051
    \\DataDirectory {s}
    \\DisableDebuggerAttachment 1
    \\UseEntryGuards 1
    \\Sandbox 1
    \\Log notice file {s}
    \\
;

const TORRC_CHAINED_TEMPLATE =
    \\SOCKSPort 127.0.0.1:9050
    \\SOCKSPort 10.200.200.1:9050
    \\DNSPort 127.0.0.1:5353
    \\DNSPort 10.200.200.1:5353
    \\ControlPort 127.0.0.1:9051
    \\OutboundBindAddress {s}
    \\DataDirectory {s}
    \\DisableDebuggerAttachment 1
    \\UseEntryGuards 1
    \\Sandbox 1
    \\Log notice file {s}
    \\
;

const DATA_DIR = "/var/lib/fella/tor";
const PID_FILE = "/var/lib/fella/tor.pid";
const LOG_FILE = "/var/lib/fella/tor/tor.log";
const TORRC_FILE = "/var/lib/fella/tor/torrc";

pub const Status = enum {
    stopped,
    starting,
    running,
    failed,
};

status: Status,
pid: i32,

pub fn create() @This() {
    const pid = loadPid();
    return .{ .status = if (pid > 0) .running else .stopped, .pid = pid };
}

fn loadPid() i32 {
    const fd = std.posix.openatZ(-100, PID_FILE, .{ .ACCMODE = .RDONLY }, 0) catch return -1;
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return -1;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    return std.fmt.parseInt(i32, trimmed, 10) catch -1;
}

fn savePid(pid: i32) !void {
    const fd = try std.posix.openatZ(-100, PID_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    _ = std.os.linux.write(fd, text.ptr, text.len);
}

fn clearPid() void {
    _ = std.os.linux.unlink(PID_FILE);
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    return self.startInternal(io, alloc, null);
}

pub fn startChained(self: *@This(), io: std.Io, alloc: std.mem.Allocator, bind_addr: []const u8) !void {
    return self.startInternal(io, alloc, bind_addr);
}

fn startInternal(self: *@This(), io: std.Io, alloc: std.mem.Allocator, bind_addr: ?[]const u8) !void {
    if (self.status == .running) {
        try Output.stdoutPrint(io, alloc, "[*] Tor already running\n", .{});
        return;
    }

    try Output.stdoutPrint(io, alloc, "[+] Starting Tor...\n", .{});

    // Ensure data directory exists
    const rc = std.os.linux.mkdir(DATA_DIR, 0o700);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        if (err != .EXIST) return error.MkdirFailed;
    }

    // Write torrc
    var torrc_buf: [4096]u8 = undefined;
    const torrc = if (bind_addr) |addr|
        try std.fmt.bufPrint(&torrc_buf, TORRC_CHAINED_TEMPLATE, .{ addr, DATA_DIR, LOG_FILE })
    else
        try std.fmt.bufPrint(&torrc_buf, TORRC_TEMPLATE, .{ DATA_DIR, LOG_FILE });

    // Append bridge configuration if a pluggable transport is available
    {
        const fd = try std.posix.openatZ(-100, TORRC_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        defer _ = std.os.linux.close(fd);
        _ = std.os.linux.write(fd, torrc.ptr, torrc.len);
        Transport.writeBridgeConfig(io, alloc, fd) catch |err| {
            try Output.stdoutPrint(io, alloc, "    [!] Bridge config failed: {any}\n", .{err});
        };
    }

    // Fork and exec tor
    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Child process
        const argv = [_:null]?[*:0]const u8{ "tor", "-f", TORRC_FILE, null };
        _ = std.os.linux.execve("/usr/bin/tor", &argv, @ptrCast(std.c.environ));
        _ = std.os.linux.execve("/bin/tor", &argv, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid < 0) {
        try Output.stdoutPrint(io, alloc, "    [!] fork failed\n", .{});
        self.status = .failed;
        return;
    }

    self.pid = @intCast(pid);
    try savePid(self.pid);

    // Wait for bootstrap
    var bootstrapped = false;
    var attempts: u8 = 0;
    while (attempts < 30) : (attempts += 1) {
        _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
        if (checkBootstrap()) {
            bootstrapped = true;
            break;
        }
    }

    if (!bootstrapped) {
        try Output.stdoutPrint(io, alloc, "    [!] Tor bootstrap timeout\n", .{});
        self.status = .failed;
        return;
    }

    self.status = .running;
    try Output.stdoutPrint(io, alloc, "    [+] Tor running on 127.0.0.1:9050\n", .{});
}

pub fn isRunning(_: *const @This()) bool {
    return checkBootstrap();
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    if (self.status != .running and self.pid <= 0) {
        try Output.stdoutPrint(io, alloc, "[*] Tor not running\n", .{});
        return;
    }

    try Output.stdoutPrint(io, alloc, "[+] Stopping Tor...\n", .{});

    if (self.pid > 0) {
        _ = std.os.linux.kill(self.pid, .TERM);
        _ = std.os.linux.nanosleep(&.{ .sec = 2, .nsec = 0 }, null);
        _ = std.os.linux.kill(self.pid, .KILL);
    }

    self.pid = -1;
    self.status = .stopped;
    clearPid();
    try Output.stdoutPrint(io, alloc, "    [+] Tor stopped\n", .{});
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    if (self.status != .running) {
        try Output.stdoutPrint(io, alloc, "[*] Tor not running, cannot rotate\n", .{});
        return;
    }

    try Output.stdoutPrint(io, alloc, "[+] Requesting new Tor circuit...\n", .{});

    // Send NEWNYM via ControlPort
    // Build sockaddr_in manually: family(2) + port(2) + addr(4) + padding(8)
    var addr: [16]u8 = undefined;
    @memset(&addr, 0);
    addr[0] = 2; // AF_INET
    addr[2] = 0x23; // port 9051 big-endian
    addr[3] = 0x5B;
    addr[4] = 127; // 127.0.0.1
    addr[5] = 0;
    addr[6] = 0;
    addr[7] = 1;

    const sock = std.os.linux.socket(2, 1, 0); // AF_INET, SOCK_STREAM
    if (sock < 0) return error.SocketFailed;
    defer _ = std.os.linux.close(@intCast(sock));

    _ = std.os.linux.connect(@intCast(sock), &addr, 16);

    const cmd = "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n";
    _ = std.os.linux.write(@intCast(sock), cmd.ptr, cmd.len);

    var resp: [256]u8 = undefined;
    _ = std.os.linux.read(@intCast(sock), &resp, resp.len);

    try Output.stdoutPrint(io, alloc, "    [+] New circuit requested\n", .{});
}

fn checkBootstrap() bool {
    // Check if SOCKS port is listening
    var addr: [16]u8 = undefined;
    @memset(&addr, 0);
    addr[0] = 2;
    addr[2] = 0x23;
    addr[3] = 0x5A;
    addr[4] = 127;
    addr[7] = 1;

    const sock = std.os.linux.socket(2, 1, 0);
    if (sock < 0) return false;
    defer _ = std.os.linux.close(@intCast(sock));

    const rc = std.os.linux.connect(@intCast(sock), &addr, 16);
    return rc == 0;
}

fn readFile(path: []const u8, buf: []u8) !usize {
    var path_z: [256:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = try std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.os.linux.close(fd);
    return try std.posix.read(fd, buf);
}

fn writeFile(path: []const u8, data: []const u8) !void {
    var path_z: [256:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = try std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}
