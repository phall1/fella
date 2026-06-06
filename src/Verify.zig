const std = @import("std");
const Output = @import("Output.zig");

const CHECK_IP_URL = "https://check.torproject.org/api/ip";
const EXPOSE_IP_URL = "https://icanhazip.com";

pub const Result = struct {
    name: []const u8,
    status: Status,
    details: []const u8,

    pub const Status = enum {
        pass,
        fail,
        warn,
    };
};

pub fn runAll(io: std.Io, alloc: std.mem.Allocator, results: *std.ArrayList(Result)) !void {
    // Tor confirmation test
    const tor_check = try checkTor(io, alloc);
    try results.append(alloc, .{
        .name = "tor_check",
        .status = if (tor_check.is_tor) .pass else .fail,
        .details = tor_check.ip,
    });

    // IP exposure test
    const exposed = try fetchUrl(alloc, EXPOSE_IP_URL, true);
    defer alloc.free(exposed);
    const real_ip = try fetchUrl(alloc, EXPOSE_IP_URL, false);
    defer alloc.free(real_ip);

    const ip_status: Result.Status = blk: {
        if (exposed.len == 0) break :blk .fail;
        if (real_ip.len == 0) break :blk .warn;
        if (std.mem.eql(u8, std.mem.trim(u8, exposed, " \n\r"), std.mem.trim(u8, real_ip, " \n\r"))) break :blk .fail;
        break :blk .pass;
    };
    try results.append(alloc, .{
        .name = "ip_exposure",
        .status = ip_status,
        .details = try alloc.dupe(u8, exposed),
    });

    // Direct bypass test
    const bypass = try fetchUrl(alloc, EXPOSE_IP_URL, false);
    defer alloc.free(bypass);
    const bypass_details = try alloc.dupe(u8, if (bypass.len == 0) "blocked" else "leaked");
    try results.append(alloc, .{
        .name = "direct_bypass",
        .status = if (bypass.len == 0) .pass else .warn,
        .details = bypass_details,
    });
}

fn checkTor(io: std.Io, alloc: std.mem.Allocator) !struct { is_tor: bool, ip: []const u8 } {
    _ = io;
    const body = try fetchUrl(alloc, CHECK_IP_URL, true);
    defer alloc.free(body);

    const is_tor = std.mem.indexOf(u8, body, "\"IsTor\":true") != null;

    const ip_start = std.mem.indexOf(u8, body, "\"IP\":\"") orelse return .{ .is_tor = is_tor, .ip = "unknown" };
    const start = ip_start + 6;
    const end = std.mem.indexOfPos(u8, body, start, "\"") orelse return .{ .is_tor = is_tor, .ip = "unknown" };
    const ip = body[start..end];
    const copied = try alloc.dupe(u8, ip);
    return .{ .is_tor = is_tor, .ip = copied };
}

fn fetchUrl(alloc: std.mem.Allocator, url: []const u8, use_proxy: bool) ![]u8 {
    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Child: redirect stdout to a temp file
        const tmp = "/tmp/fella_verify_out";
        const fd = std.os.linux.open(tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        if (fd >= 0) {
            _ = std.os.linux.dup2(@intCast(fd), 1);
            _ = std.os.linux.close(@intCast(fd));
        }
        var url_z: [512:0]u8 = undefined;
        @memcpy(url_z[0..url.len], url);
        url_z[url.len] = 0;
        if (use_proxy) {
            const argv = [_:null]?[*:0]const u8{ "curl", "-s", "--max-time", "10", "--proxy", "socks5h://127.0.0.1:9050", &url_z, null };
            _ = std.os.linux.execve("/usr/bin/curl", &argv, @ptrCast(std.c.environ));
            _ = std.os.linux.execve("/bin/curl", &argv, @ptrCast(std.c.environ));
        } else {
            const argv = [_:null]?[*:0]const u8{ "curl", "-s", "--max-time", "5", &url_z, null };
            _ = std.os.linux.execve("/usr/bin/curl", &argv, @ptrCast(std.c.environ));
            _ = std.os.linux.execve("/bin/curl", &argv, @ptrCast(std.c.environ));
        }
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);

        const tmp = "/tmp/fella_verify_out";
        const fd = std.posix.openatZ(-100, tmp, .{ .ACCMODE = .RDONLY }, 0) catch return alloc.dupe(u8, "") catch "";
        defer _ = std.os.linux.close(fd);
        var buf: [4096]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch return alloc.dupe(u8, "") catch "";
        return alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \n\r")) catch "";
    } else {
        return alloc.dupe(u8, "") catch "";
    }
}
