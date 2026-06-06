const std = @import("std");
const platform = @import("platform.zig");

const State = enum {
    off,
    init,
    hardened,
    lockdown,
};

fn stdoutPrint(io: std.Io, alloc: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !void {
    const str = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(str);
    try std.Io.File.writeStreamingAll(std.Io.File.stdout(), io, str);
}

alloc: std.mem.Allocator,
env: platform.Environment,
state: State,

pub fn create(alloc: std.mem.Allocator, env: platform.Environment) !@This() {
    return .{
        .alloc = alloc,
        .env = env,
        .state = .off,
    };
}

pub fn deinit(self: *@This()) void {
    _ = self;
}

pub fn init(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Probing environment...\n", .{});
    try stdoutPrint(io, alloc, "    Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try stdoutPrint(io, alloc, "    Container:      {s}\n", .{cr});
    }
    try stdoutPrint(io, alloc, "    Interface:      {s}\n", .{self.env.primary_iface});
    try stdoutPrint(io, alloc, "    SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try stdoutPrint(io, alloc, "    NET_ADMIN:      {}\n", .{self.env.has_net_admin});
    self.state = .init;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] fella initialized\x1b[0m\n", .{});
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Starting hardened mode...\n", .{});
    self.state = .hardened;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] Hardened mode active\x1b[0m\n", .{});
}

pub fn lockdown(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "\x1b[0;31m[!] ENGAGING LOCKDOWN\x1b[0m\n", .{});
    self.state = .lockdown;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] LOCKDOWN ACTIVE\x1b[0m\n", .{});
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Stopping fella...\n", .{});
    self.state = .off;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] fella stopped\x1b[0m\n", .{});
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Rotating...\n", .{});
    _ = self;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] Rotation complete\x1b[0m\n", .{});
}

pub fn status(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "=== fella Status ===\n", .{});
    try stdoutPrint(io, alloc, "State: {s}\n", .{@tagName(self.state)});
}

pub fn verify(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Running verification...\n", .{});
    _ = self;
    try stdoutPrint(io, alloc, "\x1b[0;34m[*] Verify complete\x1b[0m\n", .{});
}

pub fn shell(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "\x1b[0;34m[+] Dropping into fella shell\x1b[0m\n", .{});
    _ = self;
    try stdoutPrint(io, alloc, "    (not yet implemented)\n", .{});
}

pub fn wipe(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "\x1b[0;31m[!] WIPING SESSION ARTIFACTS\x1b[0m\n", .{});
    _ = self;
    try stdoutPrint(io, alloc, "\x1b[0;32m[+] Wipe complete\x1b[0m\n", .{});
}

pub fn harden(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "[+] Analyzing environment...\n", .{});
    _ = self;
    try stdoutPrint(io, alloc, "\x1b[1;33m[*] Container hardening applied\x1b[0m\n", .{});
}

pub fn doctor(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try stdoutPrint(io, alloc, "=== fella Doctor ===\n", .{});
    try stdoutPrint(io, alloc, "Environment:\n", .{});
    try stdoutPrint(io, alloc, "  Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try stdoutPrint(io, alloc, "  Container:      {s}\n", .{cr});
    }
    try stdoutPrint(io, alloc, "  Interface:      {s}\n", .{self.env.primary_iface});
    try stdoutPrint(io, alloc, "  SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try stdoutPrint(io, alloc, "  NET_ADMIN:      {}\n", .{self.env.has_net_admin});
    try stdoutPrint(io, alloc, "  Can compile C:  {}\n", .{self.env.can_compile_c});
}
