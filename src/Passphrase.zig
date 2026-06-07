const std = @import("std");
const Output = @import("Output.zig");

/// Get passphrase from FELLA_PASSPHRASE env var, or prompt if interactive.
pub fn get(io: std.Io, alloc: std.mem.Allocator) !?[]const u8 {
    // Try env var first
    const env = std.process.getEnvVarOwned(alloc, "FELLA_PASSPHRASE") catch null;
    if (env) |e| return e;

    // Try to read from /dev/tty
    const fd = std.posix.openatZ(-100, "/dev/tty", .{ .ACCMODE = .RDONLY }, 0) catch return null;
    defer _ = std.os.linux.close(fd);

    try Output.stdoutPrint(io, alloc, "Enter passphrase: ", .{});

    var buf: [256]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return null;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (trimmed.len == 0) return null;

    return try alloc.dupe(u8, trimmed);
}

pub fn isEncrypted(data: []const u8) bool {
    if (data.len < 8) return false;
    return std.mem.eql(u8, data[0..8], "FELLAENC");
}

test "isEncrypted detects magic" {
    try std.testing.expect(isEncrypted("FELLAENCdeadbeef"));
    try std.testing.expect(!isEncrypted("plain text"));
    try std.testing.expect(!isEncrypted("FELLA"));
}
