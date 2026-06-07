const std = @import("std");

pub const State = enum {
    off,
    init,
    hardened,
    lockdown,
};

const STATE_DIR = "/var/lib/fella";
const STATE_FILE = "/var/lib/fella/state";

pub fn serialize(s: State) []const u8 {
    return @tagName(s);
}

pub fn parse(text: []const u8) State {
    const trimmed = std.mem.trim(u8, text, " \n\r\t");
    if (std.mem.eql(u8, trimmed, "off")) return .off;
    if (std.mem.eql(u8, trimmed, "init")) return .init;
    if (std.mem.eql(u8, trimmed, "hardened")) return .hardened;
    if (std.mem.eql(u8, trimmed, "lockdown")) return .lockdown;
    return .off;
}

/// Load raw bytes from state file. Caller must free returned slice.
pub fn loadRaw(alloc: std.mem.Allocator) !?[]u8 {
    const fd = std.posix.openatZ(-100, STATE_FILE, .{ .ACCMODE = .RDONLY }, 0) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer _ = std.os.linux.close(fd);

    var buf: [256]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    const copy = try alloc.dupe(u8, buf[0..n]);
    return copy;
}

/// Save raw bytes to state file.
pub fn saveRaw(data: []const u8) !void {
    _ = std.os.linux.mkdir(STATE_DIR, 0o700);

    const fd = try std.posix.openatZ(-100, STATE_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}

pub fn load() !State {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const raw = try loadRaw(alloc) orelse return .off;
    return parse(raw);
}

pub fn save(s: State) !void {
    const text = serialize(s);
    var buf: [64]u8 = undefined;
    const data = std.fmt.bufPrint(&buf, "{s}\n", .{text}) catch text;
    try saveRaw(data);
}

test "serialize round-trip" {
    try std.testing.expectEqualStrings("off", serialize(.off));
    try std.testing.expectEqualStrings("init", serialize(.init));
    try std.testing.expectEqualStrings("hardened", serialize(.hardened));
    try std.testing.expectEqualStrings("lockdown", serialize(.lockdown));
}

test "parse round-trip" {
    try std.testing.expectEqual(State.off, parse("off"));
    try std.testing.expectEqual(State.init, parse("init"));
    try std.testing.expectEqual(State.hardened, parse("hardened\n"));
    try std.testing.expectEqual(State.lockdown, parse("  lockdown  "));
}

test "parse defaults to off on unknown" {
    try std.testing.expectEqual(State.off, parse("garbage"));
}
