const std = @import("std");
const Output = @import("Output.zig");

const IFNAMSIZ = 16;
const SIOCGIFHWADDR = 0x8927;
const SIOCSIFHWADDR = 0x8924;
const ARPHRD_ETHER = 1;

const VETH_HOST = "veth-fella-host";
const SAVE_DIR = "/var/lib/fella/original/mac";

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
    saveOriginal(iface) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not save original MAC for {s}: {any}\n", .{ iface, err });
    };
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
    const saved = loadOriginal(iface) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [*] No saved MAC for {s}: {any}\n", .{ iface, err });
        return;
    };
    setHwaddr(iface, saved) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not restore MAC for {s}: {any}\n", .{ iface, err });
        return;
    };
    try Output.stdoutPrint(io, alloc, "    [+] MAC restored on {s}: {s}\n", .{ iface, fmtMac(saved) });
}

// Common vendor OUIs — using a real prefix makes the MAC look legitimate
// instead of randomly generated. The last 3 bytes are randomized.
const VENDOR_OUIS = [_][3]u8{
    .{ 0x00, 0x1B, 0x21 }, // Intel
    .{ 0x00, 0x13, 0x02 }, // Intel
    .{ 0x00, 0xE0, 0x4C }, // Realtek
    .{ 0x52, 0x54, 0x00 }, // Realtek (QEMU common)
    .{ 0x00, 0x10, 0x18 }, // Broadcom
    .{ 0x00, 0x26, 0x86 }, // Qualcomm
    .{ 0x00, 0x17, 0xF2 }, // Apple
    .{ 0x00, 0x14, 0x22 }, // Dell
    .{ 0x00, 0x17, 0xA4 }, // HP
    .{ 0x00, 0x1F, 0xCC }, // Samsung
};

fn randomMac() [6]u8 {
    var buf: [6]u8 = undefined;
    _ = std.os.linux.getrandom(&buf, buf.len, 0);

    // Pick a random vendor OUI
    const oui_idx = buf[0] % VENDOR_OUIS.len;
    const oui = VENDOR_OUIS[oui_idx];

    var mac: [6]u8 = undefined;
    mac[0] = oui[0];
    mac[1] = oui[1];
    mac[2] = oui[2];
    // Last 3 bytes are fully random
    mac[3] = buf[3];
    mac[4] = buf[4];
    mac[5] = buf[5];
    return mac;
}

pub fn fmtMac(mac: [6]u8) [17:0]u8 {
    var out: [17:0]u8 = undefined;
    const s = std.fmt.bufPrint(&out, "{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}", .{
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    }) catch return out;
    out[s.len] = 0;
    return out;
}

fn saveOriginal(iface: []const u8) !void {
    _ = std.os.linux.mkdir(SAVE_DIR, 0o700);
    const mac = try getHwaddr(iface);

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ SAVE_DIR, iface });

    const fd = try std.posix.openatZ(-100, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    defer _ = std.os.linux.close(fd);
    const text = fmtMac(mac);
    const len = std.mem.indexOfScalar(u8, &text, 0) orelse text.len;
    _ = std.os.linux.write(fd, &text, len);
}

fn loadOriginal(iface: []const u8) ![6]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ SAVE_DIR, iface });

    const fd = try std.posix.openatZ(-100, path, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.os.linux.close(fd);

    var buf: [32]u8 = undefined;
    const n = try std.posix.read(fd, &buf);
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    return parseMac(trimmed);
}

fn parseMac(s: []const u8) ![6]u8 {
    var mac: [6]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, ':');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 6) return error.BadMac;
        if (part.len != 2) return error.BadMac;
        mac[i] = try std.fmt.parseInt(u8, part, 16);
        i += 1;
    }
    if (i != 6) return error.BadMac;
    return mac;
}

fn getHwaddr(iface: []const u8) ![6]u8 {
    var req: ifreq = undefined;
    @memset(std.mem.asBytes(&req), 0);
    @memcpy(req.name[0..iface.len], iface);

    const sock = std.os.linux.socket(2, 2, 0);
    if (sock > 0x7FFFFFFFFFFFFFFF) return error.SocketFailed;
    defer _ = std.os.linux.close(@intCast(sock));

    const rc = std.os.linux.ioctl(@intCast(sock), SIOCGIFHWADDR, @intFromPtr(&req));
    if (rc != 0) return error.IoctlFailed;
    if (req.hwaddr.family != ARPHRD_ETHER) return error.NotEthernet;

    var mac: [6]u8 = undefined;
    @memcpy(&mac, req.hwaddr.data[0..6]);
    return mac;
}

test "fmtMac produces correct format" {
    const mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB };
    const s = fmtMac(mac);
    try std.testing.expectEqualStrings("00:11:22:33:aa:bb", std.mem.sliceTo(&s, 0));
}

test "parseMac round-trip" {
    const mac = [6]u8{ 0x00, 0x11, 0x22, 0x33, 0xAA, 0xBB };
    const s = fmtMac(mac);
    const parsed = try parseMac(std.mem.sliceTo(&s, 0));
    try std.testing.expectEqual(mac, parsed);
}

test "randomMac uses a known vendor OUI" {
    const mac = randomMac();
    try std.testing.expect(mac[0] & 0x01 == 0); // unicast
    var found = false;
    for (VENDOR_OUIS) |oui| {
        if (mac[0] == oui[0] and mac[1] == oui[1] and mac[2] == oui[2]) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
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
