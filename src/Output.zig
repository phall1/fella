const std = @import("std");

pub const Color = struct {
    pub const reset = "\x1b[0m";
    pub const red = "\x1b[0;31m";
    pub const green = "\x1b[0;32m";
    pub const yellow = "\x1b[1;33m";
    pub const blue = "\x1b[0;34m";
};

pub fn stdoutWrite(io: std.Io, bytes: []const u8) !void {
    try std.Io.File.writeStreamingAll(std.Io.File.stdout(), io, bytes);
}

pub fn stdoutPrint(io: std.Io, alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const str = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(str);
    try stdoutWrite(io, str);
}

pub fn stderrWrite(io: std.Io, bytes: []const u8) !void {
    try std.Io.File.writeStreamingAll(std.Io.File.stderr(), io, bytes);
}

pub fn stderrPrint(io: std.Io, alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const str = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(str);
    try stderrWrite(io, str);
}
