const std = @import("std");
const Output = @import("Output.zig");

const NS_NAME = "fella";
const PID_FILE = "/var/lib/fella/cover.pid";

// Decoy endpoints that produce realistic-looking traffic shapes.
// These are public, non-sensitive endpoints chosen for low cost and
// plausible deniability. Cover traffic is not meant to hide the fact
// that a privacy tool is in use — it is meant to pad bursts and
// make traffic analysis harder against a nation-state adversary.
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

const MIN_INTERVAL_S: i64 = 30;
const MAX_INTERVAL_S: i64 = 180;
const TIMEOUT_S: i64 = 15;

pub fn start(io: std.Io, alloc: std.mem.Allocator) !void {
    // If already running, no-op
    if (isRunning()) {
        try Output.stdoutPrint(io, alloc, "[*] Cover traffic daemon already running\n", .{});
        return;
    }

    try Output.stdoutPrint(io, alloc, "[+] Starting cover traffic daemon...\n", .{});

    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Child: daemonize roughly — close stdio and run in netns
        _ = std.os.linux.close(0);
        _ = std.os.linux.close(1);
        _ = std.os.linux.close(2);

        var devnull: [16:0]u8 = undefined;
        @memcpy(devnull[0..9], "/dev/null");
        devnull[9] = 0;
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .RDONLY }, 0);
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);

        // Enter netns if it exists
        const ns_fd = std.os.linux.open("/run/netns/fella", .{ .ACCMODE = .RDONLY }, 0);
        if (ns_fd >= 0) {
            _ = std.os.linux.setns(@intCast(ns_fd), 0x40000000); // CLONE_NEWNET
            _ = std.os.linux.close(@intCast(ns_fd));
        }

        runLoop();
        std.os.linux.exit(0);
    } else if (pid > 0) {
        try savePid(@intCast(pid));
        try Output.stdoutPrint(io, alloc, "    [*] Cover traffic daemon started (pid {d})\n", .{pid});
    } else {
        return error.ForkFailed;
    }
}

pub fn stop(io: std.Io, alloc: std.mem.Allocator) !void {
    const pid = loadPid();
    if (pid <= 0) {
        try Output.stdoutPrint(io, alloc, "[*] Cover traffic daemon not running\n", .{});
        return;
    }
    _ = std.os.linux.kill(pid, .TERM);
    _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);
    _ = std.os.linux.kill(pid, .KILL);
    clearPid();
    try Output.stdoutPrint(io, alloc, "    [+] Cover traffic daemon stopped\n", .{});
}

fn runLoop() void {
    var seed_buf: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_buf, seed_buf.len, 0);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    while (true) {
        const idx = rand.int(u32) % DECOY_URLS.len;
        const url = DECOY_URLS[idx];

        fetchDecoy(url);

        const sleep_s = rand.intRangeAtMost(i64, MIN_INTERVAL_S, MAX_INTERVAL_S);
        _ = std.os.linux.nanosleep(&.{ .sec = sleep_s, .nsec = 0 }, null);
    }
}

fn fetchDecoy(url: []const u8) void {
    var script_buf: [512]u8 = undefined;
    const script = std.fmt.bufPrint(
        &script_buf,
        "#!/bin/sh\nexport TORSOCKS_CONF_FILE=/var/lib/fella/torsocks.conf\n/usr/bin/torsocks curl -fsS --max-time {d} '{s}' 2>/dev/null\n",
        .{ TIMEOUT_S, url },
    ) catch return;

    const path = "/tmp/fella_cover_fetch.sh";
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

fn isRunning() bool {
    const pid = loadPid();
    if (pid <= 0) return false;
    const rc = std.os.linux.kill(pid, @enumFromInt(0));
    return rc == 0;
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
