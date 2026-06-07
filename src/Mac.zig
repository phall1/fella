const std = @import("std");
const Output = @import("Output.zig");

const IFNAMSIZ = 16;
const SIOCSIFHWADDR = 0x8924;
const ARPHRD_ETHER = 1;

const VETH_HOST = "veth-fella-host";

const ifreq = extern struct {
    name: [IFNAMSIZ:0]u8,
    hwaddr: sockaddr,
};

const sockaddr = extern struct {
    family: u16,
    data: [14]u8,
};

pub fn rotateHost(io: std.Io, alloc: std.mem.Allocator, iface: []const u8) !void {
    if (iface.len == 0 or iface.len >= IFNAMSIZ) return;
    const mac = randomMac();
    try setHwaddr(iface, mac);
    try Output.stdoutPrint(io, alloc, "    [*] MAC rotated on {s}: {s}\n", .{ iface, fmtMac(mac) });
}

pub fn rotateVethHost(io: std.Io, alloc: std.mem.Allocator) !void {
    const mac = randomMac();
    try setHwaddr(VETH_HOST, mac);
    try Output.stdoutPrint(io, alloc, "    [*] MAC rotated on {s}: {s}\n", .{ VETH_HOST, fmtMac(mac) });
}

pub fn restoreHost(io: std.Io, alloc: std.mem.Allocator, iface: []const u8) !void {
    // Best-effort: we don't save original MACs. The host admin or DHCP
    // can restore them; this just prints a note.
    try Output.stdoutPrint(io, alloc, "    [*] Host MAC restoration skipped (use ifconfig or reboot)\n", .{});
    _ = iface;
}

fn randomMac() [6]u8 {
    var buf: [6]u8 = undefined;
    _ = std.os.linux.getrandom(&buf, buf.len, 0);
    // Locally administered + unicast
    buf[0] = (buf[0] | 0x02) & 0xfe;
    return buf;
}

fn fmtMac(mac: [6]u8) [17:0]u8 {
    var out: [17:0]u8 = undefined;
    const s = std.fmt.bufPrint(&out, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch return out;
    out[s.len] = 0;
    return out;
}

fn setHwaddr(iface: []const u8, mac: [6]u8) !void {
    var req: ifreq = undefined;
    @memset(std.mem.asBytes(&req), 0);
    @memcpy(req.name[0..iface.len], iface);

    req.hwaddr.family = ARPHRD_ETHER;
    @memcpy(req.hwaddr.data[0..6], &mac);

    const sock = std.os.linux.socket(2, 2, 0); // AF_INET, SOCK_DGRAM
    if (sock > 0x7FFFFFFFFFFFFFFF) return error.SocketFailed;
    defer _ = std.os.linux.close(@intCast(sock));

    const rc = std.os.linux.ioctl(@intCast(sock), SIOCSIFHWADDR, @intFromPtr(&req));
    if (rc != 0) return error.IoctlFailed;
}
