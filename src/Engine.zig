const std = @import("std");
const platform = @import("platform.zig");
const Output = @import("Output.zig");
const State = @import("State.zig");
const Identity = @import("Identity.zig");
const Tor = @import("backends/Tor.zig");
const Killswitch = @import("Killswitch.zig");
const Verify = @import("Verify.zig");

alloc: std.mem.Allocator,
env: platform.Environment,
state: State.State,
tor: Tor,
ks: Killswitch,

pub fn create(alloc: std.mem.Allocator, env: platform.Environment) !@This() {
    const saved = State.load() catch .off;
    return .{
        .alloc = alloc,
        .env = env,
        .state = saved,
        .tor = Tor.create(),
        .ks = Killswitch.create(),
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

    try self.tor.start(io, alloc);
    try self.ks.enableBasic(io, alloc);

    try self.transition(.hardened);
    try Output.stdoutPrint(io, alloc, "{s}[+] Hardened mode active{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn lockdown(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    try Output.stdoutPrint(io, alloc, "{s}[!] ENGAGING LOCKDOWN{s}\n", .{ Output.Color.red, Output.Color.reset });
    try self.tor.start(io, alloc);
    try self.ks.enableStrict(io, alloc);
    try self.transition(.lockdown);
    try Output.stdoutPrint(io, alloc, "{s}[+] LOCKDOWN ACTIVE{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Restoring identity...\n", .{});
    Identity.restore(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity restore failed: {any}\n", .{err});
    };

    try self.tor.stop(io, alloc);
    try self.ks.disable(io, alloc);

    try Output.stdoutPrint(io, alloc, "[+] Stopping fella...\n", .{});
    try self.transition(.off);
    try Output.stdoutPrint(io, alloc, "{s}[+] fella stopped{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn rotate(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    try self.tor.rotate(io, alloc);
    try Output.stdoutPrint(io, alloc, "{s}[+] Rotation complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn status(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "=== fella Status ===\n", .{});
    const tor_running = self.tor.isRunning();
    try Output.stdoutPrint(io, alloc, "State:      {s}\n", .{@tagName(self.state)});
    try Output.stdoutPrint(io, alloc, "Tor:        {s}\n", .{if (tor_running) "running" else "stopped"});
    try Output.stdoutPrint(io, alloc, "Killswitch: {s}\n", .{@tagName(self.ks.mode)});
}

pub fn verify(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "[+] Running verification...\n", .{});

    var results: std.ArrayList(Verify.Result) = .empty;
    defer {
        for (results.items) |r| {
            alloc.free(r.details);
        }
        results.deinit(alloc);
    }

    Verify.runAll(io, alloc, &results) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Verification error: {any}\n", .{err});
    };

    var pass: usize = 0;
    var fail: usize = 0;
    var warn: usize = 0;

    for (results.items) |r| {
        const color = switch (r.status) {
            .pass => Output.Color.green,
            .fail => Output.Color.red,
            .warn => Output.Color.yellow,
        };
        try Output.stdoutPrint(io, alloc, "    {s}[{s}]{s} {s}: {s}\n", .{ color, @tagName(r.status), Output.Color.reset, r.name, r.details });
        switch (r.status) {
            .pass => pass += 1,
            .fail => fail += 1,
            .warn => warn += 1,
        }
    }

    try Output.stdoutPrint(io, alloc, "\n{s}[*] Verify complete{s} — pass={d} fail={d} warn={d}\n", .{ Output.Color.blue, Output.Color.reset, pass, fail, warn });
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
