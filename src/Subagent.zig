const std = @import("std");
const Output = @import("Output.zig");

const NS_NAME = "fella";
const PID_DIR = "/var/lib/fella/agents";

pub const Kind = enum {
    cover,
    macrotate,
};

pub fn start(io: std.Io, alloc: std.mem.Allocator, kind: Kind) !void {
    if (isRunning(kind)) {
        try Output.stdoutPrint(io, alloc, "[*] Subagent {s} already running\n", .{@tagName(kind)});
        return;
    }

    try Output.stdoutPrint(io, alloc, "[+] Starting subagent: {s}\n", .{@tagName(kind)});

    _ = std.os.linux.mkdir(PID_DIR, 0o700);

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

        // Masquerade subagent process name too
        const PR_SET_NAME = 15;
        const sub_name = switch (kind) {
            .cover => "systemd-resolve",
            .macrotate => "systemd-network",
        };
        _ = std.os.linux.prctl(PR_SET_NAME, @intFromPtr(sub_name.ptr), 0, 0, 0);

        // Enter netns if it exists
        const ns_fd = std.os.linux.open("/run/netns/fella", .{ .ACCMODE = .RDONLY }, 0);
        if (ns_fd >= 0) {
            _ = std.os.linux.setns(@intCast(ns_fd), 0x40000000); // CLONE_NEWNET
            _ = std.os.linux.close(@intCast(ns_fd));
        }

        switch (kind) {
            .cover => runCoverLoop(),
            .macrotate => runMacRotateLoop(),
        }
        std.os.linux.exit(0);
    } else if (pid > 0) {
        try savePid(kind, @intCast(pid));
        try Output.stdoutPrint(io, alloc, "    [*] Subagent {s} started (pid {d})\n", .{ @tagName(kind), pid });
    } else {
        return error.ForkFailed;
    }
}

pub fn stop(io: std.Io, alloc: std.mem.Allocator, kind: Kind) !void {
    const pid = loadPid(kind);
    if (pid <= 0) {
        try Output.stdoutPrint(io, alloc, "[*] Subagent {s} not running\n", .{@tagName(kind)});
        return;
    }
    _ = std.os.linux.kill(pid, .TERM);
    _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
    _ = std.os.linux.kill(pid, .KILL);
    clearPid(kind);
    try Output.stdoutPrint(io, alloc, "    [+] Subagent {s} stopped\n", .{@tagName(kind)});
}

pub fn stopAll(io: std.Io, alloc: std.mem.Allocator) void {
    inline for (std.meta.fields(Kind)) |field| {
        const kind: Kind = @enumFromInt(field.value);
        stop(io, alloc, kind) catch |err| {
            _ = Output.stdoutPrint(io, alloc, "    [!] Could not stop subagent {s}: {any}\n", .{ @tagName(kind), err }) catch {};
        };
    }
}

// Constant-rate padding parameters.
// Sends a fixed-size HTTP request every PADDING_INTERVAL_MS.
// This creates a near-constant-rate tunnel stream that defeats
// size/timing correlation attacks against Tor.
const PADDING_INTERVAL_MS: i64 = 100;
const PADDING_SIZE: usize = 1024;
const PADDING_TIMEOUT_S: i64 = 5;

fn runCoverLoop() void {
    const DECOY_URLS = [_][]const u8{
        "https://www.wikipedia.org/",
        "https://www.reddit.com/",
        "https://news.ycombinator.com/",
        "https://www.bbc.com/",
        "https://github.com/",
        "https://www.apache.org/",
        "https://www.debian.org/",
        "https://archlinux.org/",
        "https://www.kernel.org/",
        "https://www.eff.org/",
    };

    var seed_buf: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_buf, seed_buf.len, 0);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    while (true) {
        const idx = rand.int(u32) % DECOY_URLS.len;
        fetchPadding(DECOY_URLS[idx], PADDING_SIZE);
        _ = std.os.linux.nanosleep(&.{ .sec = 0, .nsec = @intCast(PADDING_INTERVAL_MS * 1_000_000) }, null);
    }
}

fn runMacRotateLoop() void {
    // Rotate the veth-ns MAC every 5-15 minutes to break L2 tracking.
    var seed_buf: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_buf, seed_buf.len, 0);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    while (true) {
        rotateVethNsMac();
        const sleep_s = rand.intRangeAtMost(i64, 300, 900);
        _ = std.os.linux.nanosleep(&.{ .sec = sleep_s, .nsec = 0 }, null);
    }
}

fn fetchPadding(url: []const u8, size: usize) void {
    // Generate a fixed-size random payload so every request has identical size.
    var payload_buf: [PADDING_SIZE]u8 = undefined;
    _ = std.os.linux.getrandom(&payload_buf, size, 0);
    var payload_hex: [PADDING_SIZE * 2 + 1]u8 = undefined;
    for (payload_buf[0..size], 0..) |b, i| {
        const hi: u8 = b >> 4;
        const lo: u8 = b & 0x0f;
        payload_hex[i * 2] = if (hi < 10) '0' + hi else 'a' + (hi - 10);
        payload_hex[i * 2 + 1] = if (lo < 10) '0' + lo else 'a' + (lo - 10);
    }
    payload_hex[size * 2] = 0;

    var script_buf: [4096]u8 = undefined;
    const script = std.fmt.bufPrint(
        &script_buf,
        "#!/bin/sh\nexport TORSOCKS_CONF_FILE=/var/lib/fella/torsocks.conf\n/usr/bin/torsocks curl -fsS --max-time {d} -X POST -d '{s}' '{s}' 2>/dev/null\n",
        .{ PADDING_TIMEOUT_S, payload_hex[0 .. size * 2], url },
    ) catch return;

    const path = "/tmp/fella_padding.sh";
    _ = std.os.linux.unlink(path);

    var path_z: [256:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const fd = std.os.linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o700);
    if (fd < 0) return;
    _ = std.os.linux.write(@intCast(fd), script.ptr, script.len);
    _ = std.os.linux.close(@intCast(fd));

    const argv = [_:null]?[*:0]const u8{ "sh", path, null };
    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve("/bin/sh", &argv, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
    }
}

fn rotateVethNsMac() void {
    const SIOCSIFHWADDR = 0x8924;
    const ARPHRD_ETHER = 1;
    const IFNAMSIZ = 16;

    const ifreq = extern struct {
        name: [IFNAMSIZ:0]u8,
        hwaddr: extern struct { family: u16, data: [14]u8 },
    };

    var mac: [6]u8 = undefined;
    _ = std.os.linux.getrandom(&mac, mac.len, 0);
    mac[0] = (mac[0] | 0x02) & 0xfe;

    var req: ifreq = undefined;
    @memset(std.mem.asBytes(&req), 0);
    const iface = "veth-fella-ns";
    @memcpy(req.name[0..iface.len], iface);
    req.hwaddr.family = ARPHRD_ETHER;
    @memcpy(req.hwaddr.data[0..6], &mac);

    const sock = std.os.linux.socket(2, 2, 0);
    if (sock > 0x7FFFFFFFFFFFFFFF) return;
    defer _ = std.os.linux.close(@intCast(sock));
    _ = std.os.linux.ioctl(@intCast(sock), SIOCSIFHWADDR, @intFromPtr(&req));
}

fn pidFile(kind: Kind) [64:0]u8 {
    var buf: [64:0]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "{s}/{s}.pid", .{ PID_DIR, @tagName(kind) }) catch return buf;
    buf[s.len] = 0;
    return buf;
}

fn isRunning(kind: Kind) bool {
    const pid = loadPid(kind);
    if (pid <= 0) return false;
    const rc = std.os.linux.kill(pid, @enumFromInt(0));
    return rc == 0;
}

fn loadPid(kind: Kind) i32 {
    const path = pidFile(kind);
    const fd = std.posix.openatZ(-100, &path, .{ .ACCMODE = .RDONLY }, 0) catch return -1;
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return -1;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    return std.fmt.parseInt(i32, trimmed, 10) catch -1;
}

fn savePid(kind: Kind, pid: i32) !void {
    const path = pidFile(kind);
    const fd = try std.posix.openatZ(-100, &path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{d}\n", .{pid});
    _ = std.os.linux.write(fd, text.ptr, text.len);
}

fn clearPid(kind: Kind) void {
    const path = pidFile(kind);
    _ = std.os.linux.unlink(&path);
}
