const std = @import("std");

pub const State = enum {
    off,
    init,
    hardened,
    lockdown,
};

const STATE_DIR = "/var/lib/fella";
const STATE_FILE = "/var/lib/fella/state";

pub fn load() !State {
    const fd = std.posix.openatZ(-100, STATE_FILE, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return .off,
        else => return err,
    };
    defer _ = std.os.linux.close(fd);

    var buf: [64]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");

    if (std.mem.eql(u8, trimmed, "off")) return .off;
    if (std.mem.eql(u8, trimmed, "init")) return .init;
    if (std.mem.eql(u8, trimmed, "hardened")) return .hardened;
    if (std.mem.eql(u8, trimmed, "lockdown")) return .lockdown;

    return .off;
}

pub fn save(s: State) !void {
    const rc = std.os.linux.mkdir(STATE_DIR, 0o700);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        if (err != .EXIST) return error.MkdirFailed;
    }

    const fd = try std.posix.openatZ(-100, STATE_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);

    const text = @tagName(s);
    _ = std.os.linux.write(fd, text.ptr, text.len);
    _ = std.os.linux.write(fd, "\n", 1);
}
