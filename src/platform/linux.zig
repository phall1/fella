const std = @import("std");
const platform = @import("../platform.zig");

fn readFileZ(path: [*:0]const u8, buf: []u8) !usize {
    const fd = std.posix.openatZ(-100, path, .{ .ACCMODE = .RDONLY }, 0) catch {
        // fallback: use linux syscall directly
        const rc = std.os.linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        if (rc < 0) return error.FileNotFound;
        const fd2: i32 = @intCast(rc);
        const n = std.posix.read(fd2, buf) catch return error.ReadError;
        _ = std.os.linux.close(fd2);
        return n;
    };
    defer _ = std.os.linux.close(fd);
    return try std.posix.read(fd, buf);
}

pub fn probe(alloc: std.mem.Allocator) !platform.Environment {
    var virt_buf: [256]u8 = undefined;
    const virt_n = readFileZ("/proc/1/cgroup", &virt_buf) catch {
        return platform.Environment{
            .alloc = alloc,
            .virt = try alloc.dupe(u8, "unknown"),
            .container_runtime = null,
            .init_system = try alloc.dupe(u8, "unknown"),
            .primary_iface = try alloc.dupe(u8, "eth0"),
            .has_sys_admin = true,
            .has_net_admin = true,
            .can_compile_c = std.os.linux.access("/opt/zig/zig", 0) == 0 or
                std.os.linux.access("/usr/bin/gcc", 0) == 0 or
                std.os.linux.access("/bin/gcc", 0) == 0,
        };
    };

    const virt_str = std.mem.trim(u8, virt_buf[0..virt_n], " \n");
    const is_container = std.mem.containsAtLeast(u8, virt_str, 1, "docker") or
        std.mem.containsAtLeast(u8, virt_str, 1, "lxc") or
        std.mem.containsAtLeast(u8, virt_str, 1, "podman");

    const runtime = if (std.mem.containsAtLeast(u8, virt_str, 1, "lxc"))
        try alloc.dupe(u8, "lxc")
    else if (std.mem.containsAtLeast(u8, virt_str, 1, "docker"))
        try alloc.dupe(u8, "docker")
    else if (std.mem.containsAtLeast(u8, virt_str, 1, "podman"))
        try alloc.dupe(u8, "podman")
    else
        null;

    return platform.Environment{
        .alloc = alloc,
        .virt = try alloc.dupe(u8, if (is_container) "container" else "vm_or_baremetal"),
        .container_runtime = runtime,
        .init_system = try alloc.dupe(u8, "systemd"),
        .primary_iface = try alloc.dupe(u8, "eth0"),
        .has_sys_admin = true,
        .has_net_admin = true,
        .can_compile_c = std.os.linux.access("/opt/zig/zig", 0) == 0 or
            std.os.linux.access("/usr/bin/gcc", 0) == 0 or
            std.os.linux.access("/bin/gcc", 0) == 0,
    };
}
