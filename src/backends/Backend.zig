const std = @import("std");
const Tor = @import("Tor.zig");
const WireGuard = @import("WireGuard.zig");
const Chain = @import("Chain.zig");
const Output = @import("../Output.zig");

pub const Kind = enum {
    tor,
    wireguard,
    chain,
};

pub const Instance = union(Kind) {
    tor: Tor,
    wireguard: WireGuard,
    chain: Chain,

    pub fn create(kind: Kind) @This() {
        return switch (kind) {
            .tor => .{ .tor = Tor.create() },
            .wireguard => .{ .wireguard = WireGuard.create() },
            .chain => .{ .chain = Chain.create() },
        };
    }

    pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
        return switch (self.*) {
            .tor => |*b| b.start(io, alloc),
            .wireguard => |*b| b.start(io, alloc),
            .chain => |*b| b.start(io, alloc),
        };
    }

    pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
        return switch (self.*) {
            .tor => |*b| b.stop(io, alloc),
            .wireguard => |*b| b.stop(io, alloc),
            .chain => |*b| b.stop(io, alloc),
        };
    }

    pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
        return switch (self.*) {
            .tor => |*b| b.rotate(io, alloc),
            .wireguard => |*b| b.rotate(io, alloc),
            .chain => |*b| b.rotate(io, alloc),
        };
    }

    pub fn isRunning(self: *const @This()) bool {
        return switch (self.*) {
            .tor => |*b| b.isRunning(),
            .wireguard => |*b| b.isRunning(),
            .chain => |*b| b.isRunning(),
        };
    }

    pub fn name(self: *const @This()) []const u8 {
        return switch (self.*) {
            .tor => "tor",
            .wireguard => "wireguard",
            .chain => "chain",
        };
    }

    pub fn statusLine(self: *const @This(), io: std.Io, alloc: std.mem.Allocator) !void {
        const running = self.isRunning();
        const label = if (running) "running" else "stopped";
        try Output.stdoutPrint(io, alloc, "Backend:    {s} ({s})\n", .{ self.name(), label });
    }
};

pub fn create(kind: Kind) Instance {
    return Instance.create(kind);
}
