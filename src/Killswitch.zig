const std = @import("std");
const Output = @import("Output.zig");

const SAVE_FILE = "/var/lib/fella/iptables.save";
const KS_MODE_FILE = "/var/lib/fella/ks_mode";
const VETH_HOST = "veth-fella-host";

pub const Mode = enum {
    disabled,
    basic,
    strict,
};

mode: Mode,

pub fn create() @This() {
    return .{ .mode = loadMode() };
}

fn loadMode() Mode {
    const fd = std.posix.openatZ(-100, KS_MODE_FILE, .{ .ACCMODE = .RDONLY }, 0) catch return .disabled;
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return .disabled;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (std.mem.eql(u8, trimmed, "basic")) return .basic;
    if (std.mem.eql(u8, trimmed, "strict")) return .strict;
    return .disabled;
}

fn saveMode(mode: Mode) !void {
    const fd = try std.posix.openatZ(-100, KS_MODE_FILE, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    const text = @tagName(mode);
    _ = std.os.linux.write(fd, text.ptr, text.len);
    _ = std.os.linux.write(fd, "\n", 1);
}

fn buildBasicRuleset(out: []u8) ![]const u8 {
    return try std.fmt.bufPrint(out,
        \\*filter
        \\:INPUT DROP [0:0]
        \\:FORWARD DROP [0:0]
        \\:OUTPUT ACCEPT [0:0]
        \\-A INPUT -i lo -j ACCEPT
        \\-A OUTPUT -o lo -j ACCEPT
        \\-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        \\-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        \\-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
        \\-A INPUT -i {s} -j ACCEPT
        \\COMMIT
        \\
    , .{VETH_HOST});
}

fn buildStrictRuleset(out: []u8) ![]const u8 {
    return try std.fmt.bufPrint(out,
        \\*filter
        \\:INPUT DROP [0:0]
        \\:FORWARD DROP [0:0]
        \\:OUTPUT DROP [0:0]
        \\-A INPUT -i lo -j ACCEPT
        \\-A OUTPUT -o lo -j ACCEPT
        \\-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        \\-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        \\-A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
        \\-A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT
        \\-A OUTPUT -p tcp -d 127.0.0.1 --dport 9050 -j ACCEPT
        \\-A OUTPUT -p tcp -d 127.0.0.1 --dport 9051 -j ACCEPT
        \\-A OUTPUT -p udp -d 127.0.0.1 --dport 5353 -j ACCEPT
        \\-A INPUT -i {s} -j ACCEPT
        \\COMMIT
        \\
    , .{VETH_HOST});
}

pub fn enableBasic(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try self.save(io, alloc);

    var ruleset_buf: [1024]u8 = undefined;
    const ruleset = try buildBasicRuleset(&ruleset_buf);
    try applyRuleset(alloc, "iptables-restore", ruleset);

    const ip6ruleset =
        \\*filter
        \\:INPUT DROP [0:0]
        \\:FORWARD DROP [0:0]
        \\:OUTPUT ACCEPT [0:0]
        \\-A INPUT -i lo -j ACCEPT
        \\-A OUTPUT -o lo -j ACCEPT
        \\COMMIT
        \\
    ;
    _ = applyRuleset(alloc, "ip6tables-restore", ip6ruleset) catch {};

    try saveMode(.basic);
    self.mode = .basic;
    try Output.stdoutPrint(io, alloc, "    [+] Basic killswitch active\n", .{});
}

pub fn enableStrict(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try self.save(io, alloc);

    var ruleset_buf: [1024]u8 = undefined;
    const ruleset = try buildStrictRuleset(&ruleset_buf);
    try applyRuleset(alloc, "iptables-restore", ruleset);

    const ip6ruleset =
        \\*filter
        \\:INPUT DROP [0:0]
        \\:FORWARD DROP [0:0]
        \\:OUTPUT DROP [0:0]
        \\-A INPUT -i lo -j ACCEPT
        \\-A OUTPUT -o lo -j ACCEPT
        \\COMMIT
        \\
    ;
    _ = applyRuleset(alloc, "ip6tables-restore", ip6ruleset) catch {};

    try saveMode(.strict);
    self.mode = .strict;
    try Output.stdoutPrint(io, alloc, "    [+] Strict killswitch active\n", .{});
}

pub fn disable(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try self.restore(io, alloc);
    try saveMode(.disabled);
    self.mode = .disabled;
    try Output.stdoutPrint(io, alloc, "    [+] Killswitch disabled\n", .{});
}

fn save(self: *@This(), _: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    _ = runCmd(alloc, &.{"sh", "-c", "iptables-save -c > " ++ SAVE_FILE}) catch {};
    _ = runCmd(alloc, &.{"sh", "-c", "ip6tables-save -c > " ++ SAVE_FILE ++ ".ip6"}) catch {};
}

fn restore(self: *@This(), _: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    _ = runCmd(alloc, &.{"sh", "-c", "iptables-restore < " ++ SAVE_FILE}) catch {};
    _ = runCmd(alloc, &.{"sh", "-c", "ip6tables-restore < " ++ SAVE_FILE ++ ".ip6"}) catch {};
}

fn resolveBin(name: []const u8, out: *[128:0]u8) ?[]const u8 {
    const prefixes = [_][]const u8{"/sbin/", "/usr/sbin/", "/bin/", "/usr/bin/"};
    for (prefixes) |prefix| {
        const path = std.fmt.bufPrint(out, "{s}{s}", .{prefix, name}) catch continue;
        out[path.len] = 0;
        const rc = std.os.linux.access(out, 0);
        if (rc == 0) {
            return path;
        }
    }
    return null;
}

fn applyRuleset(alloc: std.mem.Allocator, cmd: []const u8, ruleset: []const u8) !void {
    const tmp = "/tmp/fella_iptables_rules";
    var path_z: [256:0]u8 = undefined;
    @memcpy(path_z[0..tmp.len], tmp);
    path_z[tmp.len] = 0;

    const fd = std.os.linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    if (fd > 0xFFFFFFFF) return error.OpenFailed;
    _ = std.os.linux.write(@intCast(fd), ruleset.ptr, ruleset.len);
    _ = std.os.linux.close(@intCast(fd));

    var bin_z: [128:0]u8 = undefined;
    const bin = resolveBin(cmd, &bin_z) orelse return error.CmdNotFound;
    var cmd_z: [128:0]u8 = undefined;
    @memcpy(cmd_z[0..bin.len], bin);
    cmd_z[bin.len] = 0;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        var argv_z: [64:null]?[*:0]const u8 = undefined;
        argv_z[0] = &cmd_z;
        argv_z[1] = &path_z;
        argv_z[2] = null;
        _ = std.os.linux.execve(&cmd_z, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var wstatus: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &wstatus, 0);
        if (wstatus != 0) return error.RestoreFailed;
    } else {
        return error.ForkFailed;
    }
    _ = alloc;
}

test "buildBasicRuleset contains expected patterns" {
    var buf: [1024]u8 = undefined;
    const rs = try buildBasicRuleset(&buf);
    try std.testing.expect(std.mem.indexOf(u8, rs, "COMMIT") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, ":INPUT DROP") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, ":OUTPUT ACCEPT") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, "veth-fella-host") != null);
}

test "buildStrictRuleset contains expected patterns" {
    var buf: [1024]u8 = undefined;
    const rs = try buildStrictRuleset(&buf);
    try std.testing.expect(std.mem.indexOf(u8, rs, "COMMIT") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, ":OUTPUT DROP") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, "debian-tor") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, "9050") != null);
    try std.testing.expect(std.mem.indexOf(u8, rs, "5353") != null);
}

test "Mode enum values" {
    try std.testing.expectEqual(@intFromEnum(Mode.disabled), 0);
    try std.testing.expectEqual(@intFromEnum(Mode.basic), 1);
    try std.testing.expectEqual(@intFromEnum(Mode.strict), 2);
}

fn runCmd(alloc: std.mem.Allocator, argv: []const []const u8) !void {
    _ = alloc;
    const pid = std.os.linux.fork();
    if (pid == 0) {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const arena_alloc = arena.allocator();

        var argv_z: [64:null]?[*:0]const u8 = undefined;
        for (argv, 0..) |arg, i| {
            argv_z[i] = arena_alloc.dupeZ(u8, arg) catch {
                std.os.linux.exit(1);
            };
        }
        argv_z[argv.len] = null;

        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
    } else {
        return error.ForkFailed;
    }
}
