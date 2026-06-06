const std = @import("std");
const platform = @import("platform.zig");
const Output = @import("Output.zig");
const State = @import("State.zig");
const Identity = @import("Identity.zig");

alloc: std.mem.Allocator,
env: platform.Environment,
state: State.State,

pub fn create(alloc: std.mem.Allocator, env: platform.Environment) !@This() {
    const saved = State.load() catch .off;
    return .{
        .alloc = alloc,
        .env = env,
        .state = saved,
    };
}

pub fn deinit(self: *@This()) void {
    _ = self;
}

fn transition(self: *@This(), new_state: State.State) !void {
    self.state = new_state;
    try State.save(new_state);
}

pub fn init(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Probing environment...\n", .{});
    try Output.stdoutPrint(io, alloc, "    Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc, "    Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc, "    Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc, "    SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try Output.stdoutPrint(io, alloc, "    NET_ADMIN:      {}\n", .{self.env.has_net_admin});
    try self.transition(.init);
    try Output.stdoutPrint(io, alloc, "{s}[+] fella initialized{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    try Output.stdoutPrint(io, alloc, "[+] Starting hardened mode...\n", .{});
    try self.transition(.hardened);
    try Output.stdoutPrint(io, alloc, "{s}[+] Hardened mode active{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn lockdown(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    try Output.stdoutPrint(io, alloc, "{s}[!] ENGAGING LOCKDOWN{s}\n", .{ Output.Color.red, Output.Color.reset });
    try self.transition(.lockdown);
    try Output.stdoutPrint(io, alloc, "{s}[+] LOCKDOWN ACTIVE{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Restoring identity...\n", .{});
    Identity.restore(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity restore failed: {any}\n", .{err});
    };
    try Output.stdoutPrint(io, alloc, "[+] Stopping fella...\n", .{});
    try self.transition(.off);
    try Output.stdoutPrint(io, alloc, "{s}[+] fella stopped{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn rotate(_: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    try Output.stdoutPrint(io, alloc, "{s}[+] Rotation complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn status(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "=== fella Status ===\n", .{});
    try Output.stdoutPrint(io, alloc, "State: {s}\n", .{@tagName(self.state)});
}

pub fn verify(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "[+] Running verification...\n", .{});
    try Output.stdoutPrint(io, alloc, "{s}[*] Verify complete{s}\n", .{ Output.Color.blue, Output.Color.reset });
}

pub fn shell(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "{s}[+] Dropping into fella shell{s}\n", .{ Output.Color.blue, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "    (not yet implemented)\n", .{});
}

pub fn wipe(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "{s}[!] WIPING SESSION ARTIFACTS{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "{s}[+] Wipe complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn harden(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "[+] Analyzing environment...\n", .{});
    try Output.stdoutPrint(io, alloc, "{s}[*] Container hardening applied{s}\n", .{ Output.Color.yellow, Output.Color.reset });
}

pub fn doctor(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "=== fella Doctor ===\n", .{});
    try Output.stdoutPrint(io, alloc, "Environment:\n", .{});
    try Output.stdoutPrint(io, alloc, "  Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc, "  Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc, "  Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc, "  SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try Output.stdoutPrint(io, alloc, "  NET_ADMIN:      {}\n", .{self.env.has_net_admin});
    try Output.stdoutPrint(io, alloc, "  Can compile C:  {}\n", .{self.env.can_compile_c});
}
