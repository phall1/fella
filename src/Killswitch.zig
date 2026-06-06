const std = @import("std");
const Output = @import("Output.zig");

const SAVE_FILE = "/var/lib/fella/iptables.save";
const KS_MODE_FILE = "/var/lib/fella/ks_mode";

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

pub fn enableBasic(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try self.save(io, alloc);
    try self.flush(io, alloc);

    try runCmd(io, alloc, &.{"iptables", "-P", "INPUT", "DROP"});
    try runCmd(io, alloc, &.{"iptables", "-P", "FORWARD", "DROP"});
    try runCmd(io, alloc, &.{"iptables", "-P", "OUTPUT", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"});

    try saveMode(.basic);
    self.mode = .basic;
    try Output.stdoutPrint(io, alloc, "    [+] Basic killswitch active\n", .{});
}

pub fn enableStrict(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    try self.save(io, alloc);
    try self.flush(io, alloc);

    try runCmd(io, alloc, &.{"iptables", "-P", "INPUT", "DROP"});
    try runCmd(io, alloc, &.{"iptables", "-P", "FORWARD", "DROP"});
    try runCmd(io, alloc, &.{"iptables", "-P", "OUTPUT", "DROP"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", "debian-tor", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", "9050", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-p", "tcp", "-d", "127.0.0.1", "--dport", "9051", "-j", "ACCEPT"});
    try runCmd(io, alloc, &.{"iptables", "-A", "OUTPUT", "-p", "udp", "-d", "127.0.0.1", "--dport", "5353", "-j", "ACCEPT"});

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

fn save(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    _ = runCmd(io, alloc, &.{"sh", "-c", "iptables-save -c > " ++ SAVE_FILE}) catch {};
}

fn restore(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    _ = runCmd(io, alloc, &.{"sh", "-c", "iptables-restore < " ++ SAVE_FILE}) catch {};
}

fn flush(self: *@This(), io: std.Io, alloc: std.mem.Allocator) !void {
    _ = self;
    _ = runCmd(io, alloc, &.{"iptables", "-F"}) catch {};
    _ = runCmd(io, alloc, &.{"iptables", "-t", "nat", "-F"}) catch {};
    _ = runCmd(io, alloc, &.{"iptables", "-P", "INPUT", "ACCEPT"}) catch {};
    _ = runCmd(io, alloc, &.{"iptables", "-P", "OUTPUT", "ACCEPT"}) catch {};
    _ = runCmd(io, alloc, &.{"iptables", "-P", "FORWARD", "ACCEPT"}) catch {};
    try Output.stdoutPrint(io, alloc, "    [*] iptables flushed\n", .{});
}

fn runCmd(io: std.Io, alloc: std.mem.Allocator, argv: []const []const u8) !void {
    _ = io;
    _ = alloc;
    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Child: try exec
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
        // Parent: wait
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
    } else {
        return error.ForkFailed;
    }
}
