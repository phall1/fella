const std = @import("std");
const platform = @import("platform.zig");
const Output = @import("Output.zig");
const State = @import("State.zig");
const Identity = @import("Identity.zig");
const Tor = @import("backends/Tor.zig");
const Killswitch = @import("Killswitch.zig");
const Verify = @import("Verify.zig");
const Harden = @import("Harden.zig");
const Netns = @import("Netns.zig");
const Passphrase = @import("Passphrase.zig");
const Crypto = @import("Crypto.zig");
const Wipe = @import("Wipe.zig");

alloc: std.mem.Allocator,
env: platform.Environment,
state: State.State,
tor: Tor,
ks: Killswitch,
encrypted: bool,

pub fn create(alloc: std.mem.Allocator, env: platform.Environment) !@This() {
    const saved = try loadState(alloc);
    const enc = isEncryptedMarker();
    return .{
        .alloc = alloc,
        .env = env,
        .state = saved,
        .tor = Tor.create(),
        .ks = Killswitch.create(),
        .encrypted = enc,
    };
}

fn isEncryptedMarker() bool {
    const fd = std.posix.openatZ(-100, "/var/lib/fella/.encrypted", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = std.os.linux.close(fd);
    return true;
}

fn setEncryptedMarker() !void {
    _ = std.os.linux.mkdir("/var/lib/fella", 0o700);
    const fd = try std.posix.openatZ(-100, "/var/lib/fella/.encrypted", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    _ = std.os.linux.close(fd);
}

fn loadState(alloc: std.mem.Allocator) !State.State {
    const raw = try State.loadRaw(alloc) orelse return .off;
    defer alloc.free(raw);

    if (Passphrase.isEncrypted(raw)) {
        const pass_c = std.c.getenv("FELLA_PASSPHRASE") orelse return error.NoPassphrase;
        const pass = std.mem.sliceTo(pass_c, 0);
        if (pass.len == 0) return error.NoPassphrase;

        const decrypted = try Crypto.decrypt(alloc, raw, pass);
        defer alloc.free(decrypted);

        return State.parse(decrypted);
    }
    return State.parse(raw);
}

fn saveState(self: *@This(), s: State.State) !void {
    const text = State.serialize(s);
    var buf: [64]u8 = undefined;
    const data = std.fmt.bufPrint(&buf, "{s}\n", .{text}) catch text;

    if (self.encrypted) {
        const pass_c = std.c.getenv("FELLA_PASSPHRASE") orelse return error.NoPassphrase;
        const pass = std.mem.sliceTo(pass_c, 0);
        if (pass.len == 0) return error.NoPassphrase;

        const encrypted = try Crypto.encrypt(self.alloc, data, pass);
        defer self.alloc.free(encrypted);

        try State.saveRaw(encrypted);
    } else {
        try State.saveRaw(data);
    }
}

pub fn deinit(self: *@This()) void {
    _ = self;
}

fn transition(self: *@This(), new_state: State.State) !void {
    self.state = new_state;
    try self.saveState(new_state);
}

pub fn init(self: *@This(), io: std.Io, alloc: std.mem.Allocator, encrypt: bool) !void {
    try Output.stdoutPrint(io, alloc, "[+] Probing environment...\n", .{});
    try Output.stdoutPrint(io, alloc, "    Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc, "    Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc, "    Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc, "    SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try Output.stdoutPrint(io, alloc, "    NET_ADMIN:      {}\n", .{self.env.has_net_admin});

    self.encrypted = encrypt;
    if (encrypt) {
        if (std.c.getenv("FELLA_PASSPHRASE") == null) {
            try Output.stdoutPrint(io, alloc, "    [!] Encryption requested but FELLA_PASSPHRASE not set\n", .{});
            try Output.stdoutPrint(io, alloc, "    [*] Run: export FELLA_PASSPHRASE=your_password\n", .{});
            self.encrypted = false;
        } else {
            try setEncryptedMarker();
            try Output.stdoutPrint(io, alloc, "    [*] Encrypted state enabled\n", .{});
        }
    }

    try self.transition(.init);
    try Output.stdoutPrint(io, alloc, "{s}[+] fella initialized{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn start(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    try Netns.create(io, alloc);
    try self.tor.start(io, alloc);
    try self.ks.enableBasic(io, alloc);

    try self.transition(.hardened);
    try Output.stdoutPrint(io, alloc, "{s}[+] Hardened mode active{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "    [*] Use 'fella shell' for Tor-routed subshell\n", .{});
}

pub fn lockdown(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    try Output.stdoutPrint(io, alloc, "{s}[!] ENGAGING LOCKDOWN{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Netns.create(io, alloc);
    try self.tor.start(io, alloc);
    try self.ks.enableStrict(io, alloc);
    try self.transition(.lockdown);
    try Output.stdoutPrint(io, alloc, "{s}[+] LOCKDOWN ACTIVE{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "    [*] Host outbound blocked. Use 'fella shell' for Tor-routed access.\n", .{});
}

pub fn stop(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Restoring identity...\n", .{});
    Identity.restore(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Identity restore failed: {any}\n", .{err});
    };

    try self.tor.stop(io, alloc);
    try self.ks.disable(io, alloc);
    Harden.revert(io, alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Harden revert failed: {any}\n", .{err});
    };
    Netns.destroy(io, alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Netns destroy failed: {any}\n", .{err});
    };

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
    try Netns.shell(io, alloc);
}

pub fn exec(self: *@This(), io: std.Io, alloc: std.mem.Allocator, argv: []const []const u8) !void {
    _ = self;
    try Output.stderrPrint(io, alloc, "{s}[+] Executing in fella namespace{s}\n", .{ Output.Color.blue, Output.Color.reset });
    try Netns.execNs(io, alloc, argv);
}

pub fn wipe(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc, "{s}[!] WIPING SESSION ARTIFACTS{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Wipe.dir(io, alloc, "/var/lib/fella");
    try Output.stdoutPrint(io, alloc, "{s}[+] Wipe complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn harden(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try Harden.apply(io, alloc, self.env);
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
