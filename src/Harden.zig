const std = @import("std");
const Output = @import("Output.zig");

const PROC_DIR = "/var/lib/fella/proc";
const SAVE_DIR = "/var/lib/fella/original";
const SO_PATH = "/var/lib/fella/libfella.so";
const SO_SRC_PATH = "/var/lib/fella/opsec_spoof.c";
const LD_PRELOAD_PATH = "/etc/ld.so.preload";
const PROFILE_D_PATH = "/etc/profile.d/fella.sh";
const MS_BIND: u32 = 4096;
const MNT_DETACH: u32 = 2;

const PROC_FILES = [_][]const u8{
    "/proc/cpuinfo",
    "/proc/version",
    "/proc/uptime",
    "/proc/stat",
};

const KERNEL_FILES = [_][]const u8{
    "/proc/sys/kernel/ostype",
    "/proc/sys/kernel/domainname",
    "/proc/sys/kernel/osrelease",
    "/proc/sys/kernel/version",
};

const SPOOF_C = @embedFile("harden/opsec_spoof.c");

pub fn apply(io: std.Io, alloc: std.mem.Allocator, env: anytype) !void {
    try Output.stdoutPrint(io, alloc, "[+] Hardening container fingerprints...\n", .{});

    // Ensure dirs exist
    _ = std.os.linux.mkdir(PROC_DIR, 0o700);
    _ = std.os.linux.mkdir(SAVE_DIR, 0o700);

    // Generate fake values
    const fake = try generateFakeValues(alloc);
    defer fake.deinit(alloc);

    // Save originals
    for (KERNEL_FILES) |path| {
        saveOriginal(path);
    }
    saveOriginal(LD_PRELOAD_PATH);

    // Write fake proc files
    try writeFakeProcFiles(fake);

    // Bind mount fake files over real ones (if we have CAP_SYS_ADMIN)
    if (env.has_sys_admin) {
        for (PROC_FILES) |path| {
            const fname = std.fs.path.basename(path);
            var src_z: [256:0]u8 = undefined;
            var dst_z: [256:0]u8 = undefined;
            @memset(&src_z, 0);
            @memset(&dst_z, 0);
            _ = std.fmt.bufPrint(&src_z, "{s}/{s}", .{ PROC_DIR, fname }) catch continue;
            _ = std.fmt.bufPrint(&dst_z, "{s}", .{path}) catch continue;
            _ = std.os.linux.umount2(&dst_z, MNT_DETACH);
            const rc = std.os.linux.mount(&src_z, &dst_z, null, MS_BIND, 0);
            if (rc != 0) {
                const e = std.posix.errno(rc);
                try Output.stdoutPrint(io, alloc, "    [!] bind mount failed for {s}: {s}\n", .{ path, @tagName(e) });
            } else {
                try Output.stdoutPrint(io, alloc, "    [+] Masked {s}\n", .{path});
            }
        }
    } else {
        try Output.stdoutPrint(io, alloc, "    [*] Skipping bind mounts (no SYS_ADMIN)\n", .{});
    }

    // Write fake values to writable kernel files (some may be ro in containers)
    for (KERNEL_FILES) |path| {
        const fname = std.fs.path.basename(path);
        const val = if (std.mem.eql(u8, fname, "ostype"))
            fake.ostype
        else if (std.mem.eql(u8, fname, "domainname"))
            fake.domainname
        else if (std.mem.eql(u8, fname, "release"))
            fake.release
        else if (std.mem.eql(u8, fname, "osrelease"))
            fake.release
        else if (std.mem.eql(u8, fname, "version"))
            fake.version
        else
            continue;
        writeFileZ(path, val) catch |err| {
            // AccessDenied is expected in some containers; don't spam
            if (err != error.AccessDenied) {
                try Output.stdoutPrint(io, alloc, "    [!] Could not write {s}: {any}\n", .{ path, err });
            }
            continue;
        };
        try Output.stdoutPrint(io, alloc, "    [+] Spoofed {s}\n", .{path});
    }

    // Compile and install LD_PRELOAD library
    if (env.can_compile_c) {
        var compiled_ok = true;
        compileAndInstallPreload(io, alloc) catch |err| {
            try Output.stdoutPrint(io, alloc, "    [!] LD_PRELOAD compile failed: {any}\n", .{err});
            compiled_ok = false;
        };
        if (compiled_ok) {
            // Write env var script for future shells
            var profile_buf: [1024]u8 = undefined;
            const profile = std.fmt.bufPrint(&profile_buf,
                \\export FELLA_FAKE_RELEASE="{s}"
                \\export FELLA_FAKE_VERSION="{s}"
                \\export FELLA_FAKE_MACHINE="{s}"
                \\export FELLA_FAKE_SYSNAME="{s}"
                \\export FELLA_FAKE_UPTIME="{d}"
                \\
            , .{ fake.release, fake.version, fake.machine, fake.ostype, fake.uptime }) catch null;
            if (profile) |p| {
                writeFileZ(PROFILE_D_PATH, p) catch {};
            }

            // Test compiled library (explicit LD_PRELOAD)
            const test_ok = testPreload(fake);
            if (test_ok) {
                try Output.stdoutPrint(io, alloc, "    [+] LD_PRELOAD compiled and tested\n", .{});
            } else {
                try Output.stdoutPrint(io, alloc, "    [!] LD_PRELOAD test failed\n", .{});
            }
        }
    } else {
        try Output.stdoutPrint(io, alloc, "    [*] Skipping LD_PRELOAD (no C compiler)\n", .{});
    }

    try Output.stdoutPrint(io, alloc, "{s}[+] Container hardening applied{s}\n", .{ Output.Color.yellow, Output.Color.reset });
}

pub fn revert(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Reverting container hardening...\n", .{});

    // Unmount fake proc files
    for (PROC_FILES) |path| {
        var dst_z: [256:0]u8 = undefined;
        @memset(&dst_z, 0);
        _ = std.fmt.bufPrint(&dst_z, "{s}", .{path}) catch continue;
        _ = std.os.linux.umount2(&dst_z, MNT_DETACH);
    }

    // Restore kernel files
    for (KERNEL_FILES) |path| {
        const fname = std.fs.path.basename(path);
        var save_path_z: [512:0]u8 = undefined;
        @memset(&save_path_z, 0);
        _ = std.fmt.bufPrint(&save_path_z, "{s}/{s}.txt", .{ SAVE_DIR, fname }) catch continue;
        const fd = std.posix.openatZ(-100, &save_path_z, .{ .ACCMODE = .RDONLY }, 0) catch continue;
        defer _ = std.os.linux.close(fd);
        var buf: [256]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch continue;
        writeFileZ(path, buf[0..n]) catch {};
    }

    // Remove system-wide LD_PRELOAD if present
    _ = std.os.linux.unlink(LD_PRELOAD_PATH);

    // Remove profile.d script
    _ = std.os.linux.unlink(PROFILE_D_PATH);

    // Remove compiled .so
    _ = std.os.linux.unlink(SO_PATH);
    _ = std.os.linux.unlink(SO_SRC_PATH);

    try Output.stdoutPrint(io, alloc, "    [+] Hardening reverted\n", .{});
}

const FakeValues = struct {
    ostype: []const u8,
    domainname: []const u8,
    release: []const u8,
    version: []const u8,
    machine: []const u8,
    uptime: i64,
    cpuinfo: []const u8,
    stat: []const u8,

    fn deinit(self: @This(), alloc: std.mem.Allocator) void {
        alloc.free(self.cpuinfo);
        alloc.free(self.stat);
    }
};

fn generateFakeValues(alloc: std.mem.Allocator) !FakeValues {
    const fake_release = "5.15.0-generic";
    const fake_version = "#1 SMP PREEMPT_DYNAMIC";
    const fake_machine = "x86_64";
    const fake_ostype = "Linux";
    const fake_domainname = "(none)";
    const fake_uptime: i64 = 86400;

    const cpuinfo = try generateFakeCpuinfo(alloc);
    const stat = try generateFakeStat(alloc, fake_uptime);

    return .{
        .ostype = fake_ostype,
        .domainname = fake_domainname,
        .release = fake_release,
        .version = fake_version,
        .machine = fake_machine,
        .uptime = fake_uptime,
        .cpuinfo = cpuinfo,
        .stat = stat,
    };
}

fn generateFakeCpuinfo(alloc: std.mem.Allocator) ![]const u8 {
    const fd = std.posix.openatZ(-100, "/proc/cpuinfo", .{ .ACCMODE = .RDONLY }, 0) catch {
        return alloc.dupe(u8, "processor\t: 0\nmodel name\t: Common KVM processor\n") catch "";
    };
    defer _ = std.os.linux.close(fd);

    var buf: [8192]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch {
        return alloc.dupe(u8, "processor\t: 0\nmodel name\t: Common KVM processor\n") catch "";
    };

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "model name")) {
            try out.appendSlice(alloc, "model name\t: Common KVM processor\n");
        } else if (std.mem.startsWith(u8, line, "vendor_id")) {
            try out.appendSlice(alloc, "vendor_id\t: AuthenticX86\n");
        } else if (std.mem.startsWith(u8, line, "CPU implementer")) {
            try out.appendSlice(alloc, "CPU implementer\t: 0x00\n");
        } else if (std.mem.startsWith(u8, line, "CPU part")) {
            try out.appendSlice(alloc, "CPU part\t: 0x000\n");
        } else if (std.mem.startsWith(u8, line, "Serial")) {
            try out.appendSlice(alloc, "Serial\t\t: 0000000000000000\n");
        } else if (std.mem.startsWith(u8, line, "Hardware")) {
            try out.appendSlice(alloc, "Hardware\t: Generic\n");
        } else {
            try out.appendSlice(alloc, line);
            try out.append(alloc, '\n');
        }
    }

    return out.toOwnedSlice(alloc) catch "";
}

fn generateFakeStat(alloc: std.mem.Allocator, uptime: i64) ![]const u8 {
    const fd = std.posix.openatZ(-100, "/proc/stat", .{ .ACCMODE = .RDONLY }, 0) catch {
        return alloc.dupe(u8, "btime 0\n") catch "";
    };
    defer _ = std.os.linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch {
        return alloc.dupe(u8, "btime 0\n") catch "";
    };

    // Fake btime = now - uptime
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    const now_sec: i64 = ts.sec;
    const fake_btime = now_sec - uptime;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);

    var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "btime ")) {
            var btime_buf: [64]u8 = undefined;
            const btime_line = std.fmt.bufPrint(&btime_buf, "btime {d}", .{fake_btime}) catch "btime 0";
            try out.appendSlice(alloc, btime_line);
            try out.append(alloc, '\n');
        } else {
            try out.appendSlice(alloc, line);
            try out.append(alloc, '\n');
        }
    }

    return out.toOwnedSlice(alloc) catch "";
}

fn writeFakeProcFiles(fake: FakeValues) !void {
    try writeFileZ("/var/lib/fella/proc/cpuinfo", fake.cpuinfo);

    var version_buf: [256]u8 = undefined;
    const version_line = std.fmt.bufPrint(&version_buf, "Linux version {s} (builder@generic) (gcc, GNU ld) {s}\n", .{ fake.release, fake.version }) catch "Linux version 5.15.0-generic\n";
    try writeFileZ("/var/lib/fella/proc/version", version_line);

    var uptime_buf: [64]u8 = undefined;
    const uptime_line = std.fmt.bufPrint(&uptime_buf, "{d:.2} {d:.2}\n", .{ @as(f64, @floatFromInt(fake.uptime)), @as(f64, @floatFromInt(fake.uptime)) }) catch "86400.00 86400.00\n";
    try writeFileZ("/var/lib/fella/proc/uptime", uptime_line);

    try writeFileZ("/var/lib/fella/proc/stat", fake.stat);
}

fn saveOriginal(path: []const u8) void {
    const fname = std.fs.path.basename(path);
    var save_path_z: [512:0]u8 = undefined;
    const save_path = std.fmt.bufPrint(&save_path_z, "{s}/{s}.txt", .{ SAVE_DIR, fname }) catch return;

    var path_z: [512:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    const fd = std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .RDONLY }, 0) catch {
        writeFileZ(save_path_z[0..save_path.len], "") catch {};
        return;
    };
    defer _ = std.os.linux.close(fd);

    var buf: [4096]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch 0;
    writeFileZ(save_path_z[0..save_path.len], buf[0..n]) catch {};
}

fn writeFileZ(path: []const u8, data: []const u8) !void {
    var path_z: [512:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = try std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}

fn compileAndInstallPreload(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "    [*] Compiling LD_PRELOAD library...\n", .{});

    writeFileZ(SO_SRC_PATH, SPOOF_C) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not write C source: {any}\n", .{err});
        return;
    };

    const pid = std.os.linux.fork();
    if (pid == 0) {
        const argv = [_:null]?[*:0]const u8{ "zig", "cc", "-shared", "-fPIC", "-o", SO_PATH, SO_SRC_PATH, "-ldl", null };
        _ = std.os.linux.execve("/opt/zig/zig", &argv, @ptrCast(std.c.environ));
        _ = std.os.linux.execve("/usr/bin/zig", &argv, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        if (status != 0) {
            try Output.stdoutPrint(io, alloc, "    [!] zig cc failed\n", .{});
            return error.CompileFailed;
        }
    } else {
        return error.ForkFailed;
    }
}

fn testPreload(fake: FakeValues) bool {
    const pid = std.os.linux.fork();
    if (pid == 0) {
        const cmd = "/tmp/fella_test_preload.sh";
        _ = std.os.linux.unlink(cmd);

        var script_buf: [2048]u8 = undefined;
        const script = std.fmt.bufPrint(&script_buf,
            \\#!/bin/sh
            \\export FELLA_FAKE_RELEASE="{s}"
            \\export FELLA_FAKE_VERSION="{s}"
            \\export FELLA_FAKE_MACHINE="{s}"
            \\export FELLA_FAKE_SYSNAME="{s}"
            \\export LD_PRELOAD="{s}"
            \\uname -r > /tmp/fella_test_uname.out
            \\
        , .{ fake.release, fake.version, fake.machine, fake.ostype, SO_PATH }) catch std.os.linux.exit(1);

        var path_z: [256:0]u8 = undefined;
        @memcpy(path_z[0..cmd.len], cmd);
        path_z[cmd.len] = 0;
        const fd = std.os.linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o700);
        if (fd >= 0) {
            _ = std.os.linux.write(@intCast(fd), script.ptr, script.len);
            _ = std.os.linux.close(@intCast(fd));
        }
        const argv = [_:null]?[*:0]const u8{ "sh", cmd, null };
        _ = std.os.linux.execve("/bin/sh", &argv, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        if (status != 0) return false;

        const fd = std.posix.openatZ(-100, "/tmp/fella_test_uname.out", .{ .ACCMODE = .RDONLY }, 0) catch return false;
        defer _ = std.os.linux.close(fd);
        var buf: [64]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch return false;
        return std.mem.indexOf(u8, buf[0..n], fake.release) != null;
    } else {
        return false;
    }
}
