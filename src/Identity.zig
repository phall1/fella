const std = @import("std");
const Output = @import("Output.zig");

const ORIGINAL_DIR = "/var/lib/fella/original";

fn readFileZ(path: [*:0]const u8, buf: []u8) !usize {
    const fd = std.posix.openatZ(-100, path, .{ .ACCMODE = .RDONLY }, 0) catch {
        const rc = std.os.linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        if (rc > 0x7FFFFFFFFFFFFFFF) return error.FileNotFound;
        const fd2: i32 = @intCast(rc);
        const n = std.posix.read(fd2, buf) catch return error.ReadError;
        _ = std.os.linux.close(fd2);
        return n;
    };
    defer _ = std.os.linux.close(fd);
    return try std.posix.read(fd, buf);
}

fn writeFileZ(path: [*:0]const u8, data: []const u8) !void {
    const fd = std.posix.openatZ(-100, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644) catch {
        const rc = std.os.linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        if (rc > 0x7FFFFFFFFFFFFFFF) return error.OpenFailed;
        const fd2: i32 = @intCast(rc);
        _ = std.os.linux.write(fd2, data.ptr, data.len);
        _ = std.os.linux.close(fd2);
        return;
    };
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}

fn saveOriginal(name: []const u8, data: []const u8) !void {
    _ = std.os.linux.mkdir("/var/lib/fella", 0o700);
    _ = std.os.linux.mkdir(ORIGINAL_DIR, 0o700);

    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ ORIGINAL_DIR, name });
    try writeFileZ(path, data);
}

fn hasOriginal(name: []const u8) bool {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ ORIGINAL_DIR, name }) catch return false;
    const fd = std.posix.openatZ(-100, path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = std.os.linux.close(fd);
    return true;
}

fn getOriginal(alloc: std.mem.Allocator, name: []const u8) !?[]u8 {
    var path_buf: [256]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ ORIGINAL_DIR, name });

    var buf: [4096]u8 = undefined;
    const n = readFileZ(path, &buf) catch return null;

    return try alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \n\r\t"));
}

fn getCurrentHostname(alloc: std.mem.Allocator) ![]u8 {
    var buf: [64]u8 = undefined;
    const host = try std.posix.gethostname(&buf);
    return try alloc.dupe(u8, std.mem.trim(u8, host, " \n\r\t"));
}

fn getCurrentMachineId() !?[]const u8 {
    var buf: [64]u8 = undefined;
    const n = readFileZ("/etc/machine-id", &buf) catch return null;
    return std.mem.trim(u8, buf[0..n], " \n\r\t");
}

fn getCurrentTimezone(alloc: std.mem.Allocator) ![]u8 {
    var buf: [256]u8 = undefined;
    const rc = std.os.linux.readlink("/etc/localtime", &buf, buf.len);
    if (rc > 0x7FFFFFFFFFFFFFFF) {
        // Fallback: try /etc/timezone
        const n = readFileZ("/etc/timezone", &buf) catch return try alloc.dupe(u8, "UTC");
        return try alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \n\r\t"));
    }
    const path = buf[0..@intCast(rc)];
    // Extract zone name from /usr/share/zoneinfo/...
    const prefix = "/usr/share/zoneinfo/";
    if (std.mem.startsWith(u8, path, prefix)) {
        return try alloc.dupe(u8, path[prefix.len..]);
    }
    return try alloc.dupe(u8, path);
}

fn getCurrentLocale(alloc: std.mem.Allocator) ![]u8 {
    var buf: [256]u8 = undefined;
    const n = readFileZ("/etc/default/locale", &buf) catch return try alloc.dupe(u8, "C.UTF-8");
    const content = std.mem.trim(u8, buf[0..n], " \n\r\t");
    // Parse LANG=... line
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "LANG=")) {
            return try alloc.dupe(u8, trimmed[5..]);
        }
    }
    return try alloc.dupe(u8, "C.UTF-8");
}

pub fn saveOriginalState(alloc: std.mem.Allocator) !void {
    if (hasOriginal("hostname")) return; // Already saved

    const hostname = try getCurrentHostname(alloc);
    defer alloc.free(hostname);
    try saveOriginal("hostname", hostname);

    const mid = try getCurrentMachineId();
    if (mid) |m| {
        try saveOriginal("machine-id", m);
    }

    const tz = try getCurrentTimezone(alloc);
    defer alloc.free(tz);
    try saveOriginal("timezone", tz);

    const locale = try getCurrentLocale(alloc);
    defer alloc.free(locale);
    try saveOriginal("locale", locale);
}

pub fn rotate(alloc: std.mem.Allocator) !void {
    try saveOriginalState(alloc);

    // Hostname
    var host_buf: [32]u8 = undefined;
    var tv: std.posix.timeval = undefined;
    _ = std.os.linux.gettimeofday(&tv, null);
    var prng = std.Random.DefaultPrng.init(@intCast(tv.sec + tv.usec));
    const random_hex = try std.fmt.bufPrint(&host_buf, "host-{x:0>8}", .{ prng.random().int(u32) });
    try setHostname(random_hex);

    // Machine ID
    var mid_buf: [64]u8 = undefined;
    for (0..32) |i| {
        const hex_digit: u8 = prng.random().int(u4);
        mid_buf[i] = if (hex_digit < 10) '0' + hex_digit else 'a' + (hex_digit - 10);
    }
    try writeFileZ("/etc/machine-id", mid_buf[0..32]);

    // Timezone (random from common list)
    const timezones = [_][]const u8{ "UTC", "America/New_York", "Europe/London", "Asia/Tokyo", "Europe/Berlin", "America/Los_Angeles", "Australia/Sydney" };
    const tz_idx = prng.random().int(u32) % timezones.len;
    const tz = timezones[tz_idx];
    try setTimezone(tz);

    // Locale
    const locales = [_][]const u8{ "C.UTF-8", "en_US.UTF-8", "en_GB.UTF-8" };
    const loc_idx = prng.random().int(u32) % locales.len;
    const loc = locales[loc_idx];
    try setLocale(loc);

    // Bash history
    _ = std.os.linux.unlink("/root/.bash_history");
    _ = std.os.linux.unlink("/home/phall/.bash_history");
}

pub fn restore(alloc: std.mem.Allocator) !void {
    if (try getOriginal(alloc, "hostname")) |host| {
        defer alloc.free(host);
        try setHostname(host);
    }

    if (try getOriginal(alloc, "machine-id")) |mid| {
        defer alloc.free(mid);
        try writeFileZ("/etc/machine-id", mid);
    }

    if (try getOriginal(alloc, "timezone")) |tz| {
        defer alloc.free(tz);
        try setTimezone(tz);
    }

    if (try getOriginal(alloc, "locale")) |loc| {
        defer alloc.free(loc);
        try setLocale(loc);
    }
}

fn setHostname(name: []const u8) !void {
    const rc = std.os.linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
    if (rc != 0) return error.SetHostnameFailed;

    // Also update /etc/hostname
    try writeFileZ("/etc/hostname", name);

    // Update /etc/hosts
    var hosts_buf: [4096]u8 = undefined;
    const hosts_n = readFileZ("/etc/hosts", &hosts_buf) catch 0;
    const hosts_content = hosts_buf[0..hosts_n];

    var new_hosts = std.ArrayList(u8).empty;
    defer new_hosts.deinit(std.heap.page_allocator);

    var it = std.mem.splitScalar(u8, hosts_content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t");
        if (std.mem.startsWith(u8, trimmed, "127.0.1.1")) {
            try new_hosts.appendSlice(std.heap.page_allocator, "127.0.1.1\t");
            try new_hosts.appendSlice(std.heap.page_allocator, name);
            try new_hosts.append(std.heap.page_allocator, '\n');
        } else if (std.mem.startsWith(u8, trimmed, "127.0.0.1")) {
            if (std.mem.indexOf(u8, line, "localhost") != null) {
                try new_hosts.appendSlice(std.heap.page_allocator, "127.0.0.1\tlocalhost ");
                try new_hosts.appendSlice(std.heap.page_allocator, name);
                try new_hosts.append(std.heap.page_allocator, '\n');
            } else {
                try new_hosts.appendSlice(std.heap.page_allocator, line);
                try new_hosts.append(std.heap.page_allocator, '\n');
            }
        } else {
            try new_hosts.appendSlice(std.heap.page_allocator, line);
            try new_hosts.append(std.heap.page_allocator, '\n');
        }
    }

    try writeFileZ("/etc/hosts", new_hosts.items);
}

fn setTimezone(tz: []const u8) !void {
    var target_buf: [256]u8 = undefined;
    const target = try std.fmt.bufPrintZ(&target_buf, "/usr/share/zoneinfo/{s}", .{tz});

    // Remove existing symlink
    _ = std.os.linux.unlink("/etc/localtime");

    // Create new symlink
    const rc = std.os.linux.symlink(target, "/etc/localtime");
    if (rc != 0) return error.SetTimezoneFailed;
}

fn setLocale(loc: []const u8) !void {
    var content_buf: [256]u8 = undefined;
    const content = try std.fmt.bufPrint(&content_buf, "LANG={s}\nLC_ALL={s}\n", .{ loc, loc });
    try writeFileZ("/etc/default/locale", content);
}
