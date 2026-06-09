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
const Subagent = @import("Subagent.zig");
const Masquerade = @import("Masquerade.zig");
const Mac = @import("Mac.zig");
const Ephemeral = @import("Ephemeral.zig");
const Signal = @import("Signal.zig");
const Browser = @import("Browser.zig");
const Shape = @import("Shape.zig");
const Stego = @import("Stego.zig");

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

fn hasWgConfig() bool {
    var path_z: [512:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_z, "/var/lib/fella/wireguard.conf", .{}) catch return false;
    const fd = std.posix.openatZ(-100, path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = std.os.linux.close(fd);
    return true;
}

fn loadBackendKind() Backend.Kind {
    const fd = std.posix.openatZ(-100, BACKEND_FILE, .{ .ACCMODE = .RDONLY }, 0) catch {
        // WireGuard-first: if a config exists and no backend was explicitly set,
        // prefer WireGuard over Tor. Tor is the legacy fallback.
        return if (hasWgConfig()) .wireguard else .tor;
    };
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return if (hasWgConfig()) .wireguard else .tor;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (std.mem.eql(u8, trimmed, "wireguard")) return .wireguard;
    if (std.mem.eql(u8, trimmed, "chain")) return .chain;
    return if (hasWgConfig()) .wireguard else .tor;
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

pub fn start(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, with_cover: bool, ephemeral: bool) !void {
    Signal.install();
    defer Signal.uninstall();

    // Nation-state obfuscation: rename process before anything else.
    Masquerade.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Masquerade failed: {any}\n", .{err});
    };

    if (ephemeral) {
        try Output.stdoutPrint(io, alloc_v, "[+] Engaging ephemeral mode (RAM-only session data)\n", .{});
        Ephemeral.mount(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Ephemeral mount failed: {any}\n", .{err});
        };
    }

    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    if (Signal.isInterrupted()) {
        try Output.stdoutPrint(io, alloc_v, "\n{s}[!] Interrupted — cleaning up...{s}\n", .{ Output.Color.red, Output.Color.reset });
        try self.stop(io, alloc_v);
        return error.Interrupted;
    }

    // Randomize host MAC to break L2/DHCP tracking on the primary interface.
    if (self.env.primary_iface.len > 0) {
        Mac.rotateHost(io, alloc_v, self.env.primary_iface) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Host MAC rotation failed: {any}\n", .{err});
        };
    }

    try Netns.create(io, alloc_v);
    if (Signal.isInterrupted()) {
        try Output.stdoutPrint(io, alloc_v, "\n{s}[!] Interrupted — cleaning up...{s}\n", .{ Output.Color.red, Output.Color.reset });
        try self.stop(io, alloc_v);
        return error.Interrupted;
    }

    // Randomize the host-side veth MAC too.
    Mac.rotateVethHost(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Veth MAC rotation failed: {any}\n", .{err});
    };

    try self.backend.start(io, alloc_v);
    if (Signal.isInterrupted()) {
        try Output.stdoutPrint(io, alloc_v, "\n{s}[!] Interrupted — cleaning up...{s}\n", .{ Output.Color.red, Output.Color.reset });
        try self.stop(io, alloc_v);
        return error.Interrupted;
    }

    // Apply traffic shaping and obfuscation for WireGuard-based backends
    if (isWgBackend(self.backend.name())) {
        Shape.apply(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Traffic shaping failed: {any}\n", .{err});
        };
        // Stego is best-effort; it will warn if udp2raw is not available
        _ = Stego.apply(io, alloc_v, "0.0.0.0:51820") catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Obfuscation failed: {any}\n", .{err});
        };
    }

    try self.ks.enableBasic(io, alloc_v);

    // Fail-closed: verify Tor is actually working before declaring success
    if (isTorBackend(self.backend.name())) {
        try Output.stdoutPrint(io, alloc_v, "    [*] Verifying backend connectivity...\n", .{});
        const tor_ok = Verify.quickTorCheck(alloc_v) catch false;
        if (!tor_ok) {
            try Output.stdoutPrint(io, alloc_v, "    {s}[!] Tor verification failed — traffic would leak. Stopping.{s}\n", .{ Output.Color.red, Output.Color.reset });
            try self.stop(io, alloc_v);
            return error.BackendVerifyFailed;
        }
        try Output.stdoutPrint(io, alloc_v, "    [+] Backend verified\n", .{});
    }

    if (with_cover) {
        Subagent.start(io, alloc_v, .cover) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Cover subagent failed: {any}\n", .{err});
        };
    }

    // Lock down this process after Tor and netns are set up.
    Sandbox.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Sandbox setup failed: {any}\n", .{err});
    };
    try self.transition(.hardened);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] Hardened mode active{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc_v, "    [*] Backend: {s} | Use 'fella shell' for routed subshell\n", .{self.backend.name()});
}

pub fn lockdown(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator, with_cover: bool, ephemeral: bool) !void {
    Signal.install();
    defer Signal.uninstall();

    Masquerade.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Masquerade failed: {any}\n", .{err});
    };

    if (ephemeral) {
        try Output.stdoutPrint(io, alloc_v, "[+] Engaging ephemeral mode (RAM-only session data)\n", .{});
        Ephemeral.mount(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Ephemeral mount failed: {any}\n", .{err});
        };
    }

    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };

    if (self.env.primary_iface.len > 0) {
        Mac.rotateHost(io, alloc_v, self.env.primary_iface) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Host MAC rotation failed: {any}\n", .{err});
        };
    }

    try Output.stdoutPrint(io, alloc_v, "{s}[!] ENGAGING LOCKDOWN{s}\n", .{ Output.Color.red, Output.Color.reset });
    try Netns.create(io, alloc_v);
    if (Signal.isInterrupted()) {
        try Output.stdoutPrint(io, alloc_v, "\n{s}[!] Interrupted — cleaning up...{s}\n", .{ Output.Color.red, Output.Color.reset });
        try self.stop(io, alloc_v);
        return error.Interrupted;
    }

    Mac.rotateVethHost(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Veth MAC rotation failed: {any}\n", .{err});
    };
    try self.backend.start(io, alloc_v);
    if (Signal.isInterrupted()) {
        try Output.stdoutPrint(io, alloc_v, "\n{s}[!] Interrupted — cleaning up...{s}\n", .{ Output.Color.red, Output.Color.reset });
        try self.stop(io, alloc_v);
        return error.Interrupted;
    }

    // Apply traffic shaping and obfuscation for WireGuard-based backends
    if (isWgBackend(self.backend.name())) {
        Shape.apply(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Traffic shaping failed: {any}\n", .{err});
        };
        _ = Stego.apply(io, alloc_v, "0.0.0.0:51820") catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Obfuscation failed: {any}\n", .{err});
        };
    }

    try self.ks.enableStrict(io, alloc_v);

    // Fail-closed: verify Tor is actually working before declaring success
    if (isTorBackend(self.backend.name())) {
        try Output.stdoutPrint(io, alloc_v, "    [*] Verifying backend connectivity...\n", .{});
        const tor_ok = Verify.quickTorCheck(alloc_v) catch false;
        if (!tor_ok) {
            try Output.stdoutPrint(io, alloc_v, "    {s}[!] Tor verification failed — traffic would leak. Stopping.{s}\n", .{ Output.Color.red, Output.Color.reset });
            try self.stop(io, alloc_v);
            return error.BackendVerifyFailed;
        }
        try Output.stdoutPrint(io, alloc_v, "    [+] Backend verified\n", .{});
    }

    if (with_cover) {
        Subagent.start(io, alloc_v, .cover) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Cover subagent failed: {any}\n", .{err});
        };
    }

    Sandbox.apply(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Sandbox setup failed: {any}\n", .{err});
    };
    try self.transition(.lockdown);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] LOCKDOWN ACTIVE{s}\n", .{ Output.Color.green, Output.Color.reset });
    try Output.stdoutPrint(io, alloc_v, "    [*] Host outbound blocked. Use 'fella shell' for routed access.\n", .{});
}

fn isTorBackend(name: []const u8) bool {
    return std.mem.eql(u8, name, "tor") or std.mem.eql(u8, name, "chain");
}

fn isWgBackend(name: []const u8) bool {
    return std.mem.eql(u8, name, "wireguard") or std.mem.eql(u8, name, "chain");
}

pub fn stop(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Restoring identity...\n", .{});
    Identity.restore(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity restore failed: {any}\n", .{err});
    };

    Subagent.stopAll(io, alloc_v);

    // Tear down shaping and obfuscation before the backend
    if (isWgBackend(self.backend.name())) {
        Shape.remove(io, alloc_v) catch {};
        Stego.remove(io, alloc_v);
    }

    try self.backend.stop(io, alloc_v);
    try self.ks.disable(io, alloc_v);
    Harden.revert(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Harden revert failed: {any}\n", .{err});
    };
    Netns.destroy(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Netns destroy failed: {any}\n", .{err});
    };

    if (self.env.primary_iface.len > 0) {
        Mac.restoreHost(io, alloc_v, self.env.primary_iface) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Host MAC restore failed: {any}\n", .{err});
        };
    }

    if (Ephemeral.isMounted()) {
        Ephemeral.unmount(io, alloc_v) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Ephemeral unmount failed: {any}\n", .{err});
        };
    }

    try Output.stdoutPrint(io, alloc_v, "[+] Stopping fella...\n", .{});
    try self.transition(.off);
    try Output.stdoutPrint(io, alloc_v, "{s}[+] fella stopped{s}\n", .{ Output.Color.green, Output.Color.reset });
}

pub fn rotate(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc_v, "[+] Rotating identity...\n", .{});
    Identity.rotate(alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Identity rotation failed: {any}\n", .{err});
    };
    if (self.env.primary_iface.len > 0) {
        Mac.rotateHost(io, alloc_v, self.env.primary_iface) catch |err| {
            try Output.stdoutPrint(io, alloc_v, "    [!] Host MAC rotation failed: {any}\n", .{err});
        };
    }
    Mac.rotateVethHost(io, alloc_v) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "    [!] Veth MAC rotation failed: {any}\n", .{err});
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
    try Output.stdoutPrint(io, alloc_v, "Ephemeral:  {s}\n", .{if (Ephemeral.isMounted()) "RAM-only" else "disk"});
}

pub fn statusJson(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    const json = try std.fmt.allocPrint(alloc_v, "{{\"backend\":\"{s}\",\"state\":\"{s}\",\"killswitch\":\"{s}\",\"seccomp\":{},\"ephemeral\":{}}}\n", .{
        self.backend.name(),
        @tagName(self.state),
        @tagName(self.ks.mode),
        Sandbox.isActive(),
        Ephemeral.isMounted(),
    });
    defer alloc_v.free(json);
    try Output.stdoutWrite(io, json);
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

pub fn verifyJson(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    var results: std.ArrayList(Verify.Result) = .empty;
    defer {
        for (results.items) |r| {
            alloc_v.free(r.details);
        }
        results.deinit(alloc_v);
    }

    Verify.runAll(io, alloc_v, &results) catch |err| {
        try Output.stdoutPrint(io, alloc_v, "{{\"error\":\"{any}\"}}\n", .{err});
        return;
    };

    var pass: usize = 0;
    var fail: usize = 0;
    var warn: usize = 0;
    for (results.items) |r| {
        switch (r.status) {
            .pass => pass += 1,
            .fail => fail += 1,
            .warn => warn += 1,
        }
    }

    try Output.stdoutPrint(io, alloc_v, "{{\"pass\":{d},\"fail\":{d},\"warn\":{d},\"results\":[", .{ pass, fail, warn });
    for (results.items, 0..) |r, i| {
        if (i > 0) try Output.stdoutWrite(io, ",");
        try Output.stdoutPrint(io, alloc_v, "{{\"name\":\"{s}\",\"status\":\"{s}\",\"details\":\"", .{ r.name, @tagName(r.status) });
        for (r.details) |c| {
            if (c == '"') {
                try Output.stdoutWrite(io, "\\\"");
            } else if (c == '\\') {
                try Output.stdoutWrite(io, "\\\\");
            } else if (c >= 0x20 and c < 0x7f) {
                try Output.stdoutWrite(io, &[_]u8{c});
            } else {
                try Output.stdoutWrite(io, "?");
            }
        }
        try Output.stdoutWrite(io, "\"}");
    }
    try Output.stdoutWrite(io, "]}\n");
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

    // Environment
    try Output.stdoutPrint(io, alloc_v, "Environment:\n", .{});
    try Output.stdoutPrint(io, alloc_v, "  Virtualization: {s}\n", .{self.env.virt});
    if (self.env.container_runtime) |cr| {
        try Output.stdoutPrint(io, alloc_v, "  Container:      {s}\n", .{cr});
    }
    try Output.stdoutPrint(io, alloc_v, "  Interface:      {s}\n", .{self.env.primary_iface});
    try Output.stdoutPrint(io, alloc_v, "  SYS_ADMIN:      {s}\n", .{if (self.env.has_sys_admin) "yes" else "NO"});
    try Output.stdoutPrint(io, alloc_v, "  NET_ADMIN:      {s}\n", .{if (self.env.has_net_admin) "yes" else "NO"});
    try Output.stdoutPrint(io, alloc_v, "  Can compile C:  {s}\n", .{if (self.env.can_compile_c) "yes" else "no"});

    // Required binaries
    try Output.stdoutPrint(io, alloc_v, "\nDependencies:\n", .{});
    const bins = .{
        .{ "tor", "/usr/bin/tor" },
        .{ "torsocks", "/usr/bin/torsocks" },
        .{ "iptables", "/sbin/iptables" },
        .{ "ip6tables", "/sbin/ip6tables" },
        .{ "ip", "/sbin/ip" },
        .{ "wg", "/usr/bin/wg" },
    };
    inline for (bins) |bin| {
        const present = binExists(bin[1]);
        const color = if (present) Output.Color.green else Output.Color.yellow;
        try Output.stdoutPrint(io, alloc_v, "  {s}{s}{s}: {s}\n", .{ color, bin[0], Output.Color.reset, if (present) "found" else "not found" });
    }

    // State directory writable
    const state_ok = stateDirWritable();
    try Output.stdoutPrint(io, alloc_v, "\nState directory (/var/lib/fella): {s}\n", .{if (state_ok) "writable" else "NOT WRITABLE"});

    // Backend status
    try Output.stdoutPrint(io, alloc_v, "\nBackend:\n", .{});
    try self.backend.statusLine(io, alloc_v);

    try Sandbox.describe(io, alloc_v);
}

pub fn doctorJson(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    const sa = if (self.env.has_sys_admin) "true" else "false";
    const na = if (self.env.has_net_admin) "true" else "false";
    const cc = if (self.env.can_compile_c) "true" else "false";
    try Output.stdoutPrint(io, alloc_v, "{{\"virtualization\":\"{s}\",\"interface\":\"{s}\",\"sys_admin\":{s},\"net_admin\":{s},\"can_compile_c\":{s}}}\n", .{
        self.env.virt,
        self.env.primary_iface,
        sa,
        na,
        cc,
    });
}

fn binExists(path: []const u8) bool {
    var path_z: [256:0]u8 = undefined;
    if (path.len >= path_z.len) return false;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const rc = std.os.linux.access(&path_z, 0);
    return rc == 0;
}

fn stateDirWritable() bool {
    const rc = std.os.linux.access("/var/lib/fella", 2); // W_OK
    if (rc == 0) return true;
    // Try to create it
    const mk = std.os.linux.mkdir("/var/lib/fella", 0o700);
    return mk == 0 or std.posix.errno(mk) == .EXIST;
}

pub fn coverStart(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Subagent.start(io, alloc_v, .cover);
}

pub fn coverStop(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Subagent.stop(io, alloc_v, .cover);
}

pub fn macRotateStart(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Subagent.start(io, alloc_v, .macrotate);
}

pub fn macRotateStop(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    try Subagent.stop(io, alloc_v, .macrotate);
}

pub fn browser(self: *@This(), io: std.Io, alloc_v: std.mem.Allocator) !void {
    _ = self;
    const locale = Identity.getCurrentLocale(alloc_v) catch "en-US";
    defer alloc_v.free(locale);
    try Browser.launch(io, alloc_v, locale);
}
