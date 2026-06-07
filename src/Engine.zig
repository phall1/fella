const std = @import("std");
const platform = @import("platform.zig");
const Output = @import("Output.zig");
const State = @import("State.zig");
const Identity = @import("Identity.zig");
const Backend = @import("backends/Backend.zig");
const Killswitch = @import("Killswitch.zig");
const Verify = @import("Verify.zig");
const Harden = @import("Harden.zig");
const Netns = @import("Netns.zig");
const Passphrase = @import("Passphrase.zig");
const Crypto = @import("Crypto.zig");
const Wipe = @import("Wipe.zig");
const Sandbox = @import("Sandbox.zig");
const Cover = @import("Cover.zig");

const BACKEND_FILE = "/var/lib/fella/backend_kind";

alloc: std.mem.Allocator,
env: platform.Environment,
state: State.State,
backend: Backend.Instance,
ks: Killswitch,
encrypted: bool,

pub fn create(alloc_v: std.mem.Allocator, env: platform.Environment) !@This() {
    const saved = try loadState(alloc_v);
    const enc = isEncryptedMarker();
    const kind = loadBackendKind();
    return .{
        .alloc = alloc_v,
        .env = env,
        .state = saved,
        .backend = Backend.create(kind),
        .ks = Killswitch.create(),
        .encrypted = enc,
    };
}

fn loadBackendKind() Backend.Kind {
    const fd = std.posix.openatZ(-100, BACKEND_FILE, .{ .ACCMODE = .RDONLY }, 0) catch return .tor;
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return .tor;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (std.mem.eql(u8, trimmed, "wireguard")) return .wireguard;
    if (std.mem.eql(u8, trimmed, "chain")) return .chain;
    return .tor;
}

fn saveBackendKind(kind: Backend.Kind) !void {
    _ = std.os.linux.mkdir("/var/lib/fella", 0o700);
    const fd = try std.posix.openatZ(-100, BACKEND_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer _ = std.os.linux.close(fd);
    const text = @tagName(kind);
    _ = std.os.linux.write(fd, text.ptr, text.len);
    _ = std.os.linux.write(fd, "\n", 1);
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

fn loadState(alloc_v: std.mem.Allocator) !State.State {
    const raw = try State.loadRaw(alloc_v) orelse return .off;
    defer alloc_v.free(raw);

    if (Passphrase.isEncrypted(raw)) {
        const pass_c = std.c.getenv("FELLA_PASSPHRASE") orelse return error.NoPassphrase;
        const pass = std.mem.sliceTo(pass_c, 0);
        if (pass.len == 0) return error.NoPassphrase;

        const decrypted = try Crypto.decrypt(alloc_v, raw, pass);
        defer alloc_v.free(decrypted);

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

pub fn init(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, encrypt: bool, backend_kind: Backend.Kind) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Probing environment...\n", .{});
    try Output.stdoutPrint(io, alloc_v, "    Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc_v, "    Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc_v, "    Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc_v, "    SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try Output.stdoutPrint(io, alloc_v, "    NET_ADMIN:      {}\n", .{self.env.has_net_admin});

    self.encrypted = encrypt;
    if (encrypt) {
        if (std.c.getenv("FELLA_PASSPHRASE") == null) {
            try Output.stdoutPrint(io, alloc_v, "    [!] Encryption requested but FELLA_PASSPHRASE not set\n", .{});
            try Output.stdoutPrint(io, alloc_v, "    [*] Run: export FELLA_PASSPHRASE=your_password\n", .{});
            self.encrypted = false;
        } else {
            try setEncryptedMarker();
            try Output.stdoutPrint(io, alloc_v, "    [*] Encrypted state enabled\n", .{});
        }
    }

    try saveBackendKind(backend_kind);
    self.backend = Backend.create(backend_kind);
    try Output.stdoutPrint(io, alloc_v, "    [*] Backend: {s}\n", .{@tagName(backend_kind)});

    try self.transition(.init);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] fella initialized{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn start(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, with_cover: bool) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    try Netns.create(io, alloc_v);
    try self.backend.start(io, alloc_v);
    try self.ks.enableBasic(io, alloc_v);

    if (with_cover) {
        Cover.start(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Cover traffic failed: {any}\n", .{err});
        };
    }

    // Lock down this process after Tor and netns are set up.
    var sandbox_ok = true;
    Sandbox.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Sandbox setup failed: {any}\n", .{err});
        sandbox_ok = false;
    };
    try self.transition(.hardened);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] Hardened mode active{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc_v, "    [*] Backend: {s} | Use 'fella shell' for routed subshell\n", .{self.backend.name()});
}

pub fn lockdown(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, with_cover: bool) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    try Output.stdoutPrint(io, alloc_v, "{s}[!] ENGAGING LOCKDOWN{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Netns.create(io, alloc_v);
    try self.backend.start(io, alloc_v);
    try self.ks.enableStrict(io, alloc_v);

    if (with_cover) {
        Cover.start(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Cover traffic failed: {any}\n", .{err});
        };
    }

    Sandbox.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Sandbox setup failed: {any}\n", .{err});
    };
    try self.transition(.lockdown);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] LOCKDOWN ACTIVE{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc_v, "    [*] Host outbound blocked. Use 'fella shell' for routed access.\n", .{});
}

pub fn stop(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Restoring identity...\n", .{});
    Identity.restore(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity restore failed: {any}\n", .{err});
    };

    Cover.stop(io, alloc_v) catch {};
    try self.backend.stop(io, alloc_v);
    try self.ks.disable(io, alloc_v);
    Harden.revert(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Harden revert failed: {any}\n", .{err});
    };
    Netns.destroy(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Netns destroy failed: {any}\n", .{err});
    };

    try Output.stdoutPrint(io, alloc_v, "[+] Stopping fella...\n", .{});
    try self.transition(.off);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] fella stopped{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn rotate(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    try self.backend.rotate(io, alloc_v);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] Rotation complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn status(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "=== fella Status ===\n", .{});
    try self.backend.statusLine(io, alloc_v);
    try Output.stdoutPrint(io, alloc_v, "State:      {s}\n", .{@tagName(self.state)});
    try Output.stdoutPrint(io, alloc_v, "Killswitch: {s}\n", .{@tagName(self.ks.mode)});
    try Output.stdoutPrint(io, alloc_v, "Seccomp:    {s}\n", .{if (Sandbox.isActive()) "filter active" else "inactive"});
}

pub fn verify(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc_v, "[+] Running verification...\n", .{});

    var results: std.ArrayList(Verify.Result) = .empty;
    defer {
        for (results.items) |r| {
            alloc_v.free(r.details);
        }
        results.deinit(alloc_v);
    }

    Verify.runAll(io, alloc_v, &results) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Verification error: {any}\n", .{err});
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
        try Output.stdoutPrint(io, alloc_v, "    {s}[{s}]{s} {s}: {s}\n", .{ color, @tagName(r.status), Output.Color.reset, r.name, r.details });
        switch (r.status) {
            .pass => pass += 1,
            .fail => fail += 1,
            .warn => warn += 1,
        }
    }

    try Output.stdoutPrint(io, alloc_v, "\n{s}[*] Verify complete{s} — pass={d} fail={d} warn={d}\n", .{ Output.Color.blue, Output.Color.reset, pass, fail, warn });
}

pub fn shell(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Netns.shell(io, alloc_v);
}

pub fn exec(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, argv: []const []const u8) !void {
    _ = self;
    try Output.stderrPrint(io, alloc_v, "{s}[+] Executing in fella namespace{s}\n", .{ Output.Color.blue, Output.Color.reset });
    try Netns.execNs(io, alloc_v, argv);
}

pub fn wipe(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Output.stdoutPrint(io, alloc_v, "{s}[!] WIPING SESSION ARTIFACTS{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Wipe.dir(io, alloc_v, "/var/lib/fella");
    try Output.stdoutPrint(io, alloc_v, "{s}[+] Wipe complete{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn harden(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Harden.apply(io, alloc_v, self.env);
}

pub fn doctor(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "=== fella Doctor ===\n", .{});
    try Output.stdoutPrint(io, alloc_v, "Environment:\n", .{});
    try Output.stdoutPrint(io, alloc_v, "  Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc_v, "  Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc_v, "  Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc_v, "  SYS_ADMIN:      {}\n", .{self.env.has_sys_admin});
    try Output.stdoutPrint(io, alloc_v, "  NET_ADMIN:      {}\n", .{self.env.has_net_admin});
    try Output.stdoutPrint(io, alloc_v, "  Can compile C:  {}\n", .{self.env.can_compile_c});
    try Sandbox.describe(io, alloc_v);
}

pub fn coverStart(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Cover.start(io, alloc_v);
}

pub fn coverStop(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Cover.stop(io, alloc_v);
}
