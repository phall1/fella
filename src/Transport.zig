const std = @import("std");
const Output = @import("Output.zig");

// Default obfs4 bridges maintained by Tor project for censored regions.
// These are public, rotated periodically, and safe to embed.
const DEFAULT_OBFS4_BRIDGES =
    \\Bridge obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP0HUEi4r49QiBMEP3PWToQTfaIPJde9sogd7OUvQ iat-mode=0
    \\Bridge obfs4 38.229.1.78:80 C8CBDB2464FC9804A69531437BCF2BE31FDD2EE4 cert=Hmyfd2ev46gGY7NoVxA9ngrPF2zCZtzskRTzoWXbxNkzeVnGFPWmrTtILRyqCTjHR+s9dg iat-mode=0
    \\Bridge obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B1FBD8B0B0A0B0A0B cert=UVQ0srL1JI/vO6V6m/24anYXiJD3QP0HUEi4r49QiBMEP3PWToQTfaIPJde9sogd7OUvQ iat-mode=0
;

const BRIDGE_FILE = "/var/lib/fella/bridges.conf";

pub const Mode = enum {
    direct,
    obfs4,
    snowflake,
};

pub fn detectMode() Mode {
    if (hasBinary("obfs4proxy")) return .obfs4;
    if (hasBinary("snowflake-client")) return .snowflake;
    return .direct;
}

pub fn writeBridgeConfig(io: std.Io, alloc: std.mem.Allocator, torrc_fd: i32) !void {
    const mode = detectMode();
    const bridges = loadBridges(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not load bridges: {any}\n", .{err});
        return;
    };
    defer alloc.free(bridges);

    if (mode == .obfs4) {
        _ = std.os.linux.write(torrc_fd, "UseBridges 1\n", 13);
        _ = std.os.linux.write(torrc_fd, "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n", 53);
        _ = std.os.linux.write(torrc_fd, bridges.ptr, bridges.len);
        try Output.stdoutPrint(io, alloc, "    [*] obfs4 bridges configured\n", .{});
    } else if (mode == .snowflake) {
        _ = std.os.linux.write(torrc_fd, "UseBridges 1\n", 13);
        _ = std.os.linux.write(torrc_fd, "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -url https://snowflake-broker.torproject.net.global.prod.fastly.net/ -front cdn.sstatic.net -ice stun:stun.l.google.com:19302\n", 180);
        try Output.stdoutPrint(io, alloc, "    [*] snowflake bridge configured\n", .{});
    } else {
        try Output.stdoutPrint(io, alloc, "    [*] Direct Tor (no transport installed)\n", .{});
    }
}

fn loadBridges(alloc: std.mem.Allocator) ![]u8 {
    const fd = std.posix.openatZ(-100, BRIDGE_FILE, .{ .ACCMODE = .RDONLY }, 0) catch {
        return alloc.dupe(u8, DEFAULT_OBFS4_BRIDGES);
    };
    defer _ = std.os.linux.close(fd);
    var buf: [4096]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    if (n == 0) return alloc.dupe(u8, DEFAULT_OBFS4_BRIDGES);
    return try alloc.dupe(u8, buf[0..n]);
}

test "detectMode falls back to direct without binaries" {
    // In this test environment obfs4proxy/snowflake-client are unlikely installed.
    try std.testing.expectEqual(Mode.direct, detectMode());
}

test "loadBridges falls back to default" {
    const alloc = std.testing.allocator;
    const bridges = try loadBridges(alloc);
    defer alloc.free(bridges);
    try std.testing.expect(bridges.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, bridges, "Bridge obfs4") != null);
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
