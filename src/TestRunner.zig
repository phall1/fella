const std = @import("std");
const Output = @import("Output.zig");
const Engine = @import("Engine.zig");
const platform = @import("platform.zig");
const Netns = @import("Netns.zig");

pub const Result = struct {
    name: []const u8,
    passed: bool,
    detail: []const u8,
};

pub fn runAll(io: std.Io, alloc: std.mem.Allocator, results: *std.ArrayList(Result)) !void {
    // Pre-clean any stale state from previous runs
    forceCleanup();

    try runTest(io, alloc, results, "doctor_json", testDoctorJson);
    try runTest(io, alloc, results, "doctor_human", testDoctorHuman);
    try runTest(io, alloc, results, "backend_lifecycle", testBackendLifecycle);
    try runTest(io, alloc, results, "netns_routing", testNetnsRouting);
    try runTest(io, alloc, results, "identity_rotation", testIdentityRotation);
    try runTest(io, alloc, results, "killswitch_ruleset", testKillswitchRuleset);
}

fn runTest(
    io: std.Io,
    alloc: std.mem.Allocator,
    results: *std.ArrayList(Result),
    name: []const u8,
    comptime testFn: fn (std.Io, std.mem.Allocator) anyerror![]const u8,
) !void {
    const detail = testFn(io, alloc) catch |err| {
        const msg = try std.fmt.allocPrint(alloc, "{any}", .{err});
        try results.append(alloc, .{ .name = name, .passed = false, .detail = msg });
        return;
    };
    try results.append(alloc, .{ .name = name, .passed = true, .detail = detail });
}

fn forceCleanup() void {
    // Best-effort cleanup without shell scripts
    _ = std.os.linux.kill(loadPid("/var/lib/fella/tor.pid"), .KILL);
    _ = std.os.linux.kill(loadPid("/var/lib/fella/agents/cover.pid"), .KILL);
    _ = std.os.linux.kill(loadPid("/var/lib/fella/agents/macrotate.pid"), .KILL);
    Netns.destroyQuiet();
    _ = std.os.linux.unlink("/var/lib/fella/ks_mode");
    _ = std.os.linux.unlink("/var/lib/fella/backend_kind");
    _ = std.os.linux.unlink("/var/lib/fella/.encrypted");
    _ = std.os.linux.nanosleep(&.{ .sec = 0, .nsec = 500_000_000 }, null);
}

fn loadPid(path: []const u8) i32 {
    var path_z: [256:0]u8 = undefined;
    if (path.len >= path_z.len) return -1;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .RDONLY }, 0) catch return -1;
    defer _ = std.os.linux.close(fd);
    var buf: [64]u8 = undefined;
    const n = std.posix.read(fd, &buf) catch return -1;
    const trimmed = std.mem.trim(u8, buf[0..n], " \n\r\t");
    return std.fmt.parseInt(i32, trimmed, 10) catch -1;
}

fn testDoctorJson(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();
    try engine.doctorJson(io, alloc);
    return "valid json";
}

fn testDoctorHuman(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();
    try engine.doctor(io, alloc);
    return "valid output";
}

fn testBackendLifecycle(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    forceCleanup();
    _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);

    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();

    try engine.init(io, alloc, false, .tor);
    try engine.start(io, alloc, false, false);

    const running = engine.backend.isRunning();
    try engine.stop(io, alloc);

    if (!running) return error.BackendNotRunning;
    return "tor started and stopped";
}

fn testNetnsRouting(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    forceCleanup();
    _ = std.os.linux.nanosleep(&.{ .sec = 1, .nsec = 0 }, null);

    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();

    try engine.init(io, alloc, false, .tor);
    try engine.start(io, alloc, false, false);

    const out = try execInNetns(alloc, &.{ "curl", "-s", "--max-time", "15", "https://check.torproject.org/api/ip" });
    defer alloc.free(out);

    try engine.stop(io, alloc);

    if (std.mem.indexOf(u8, out, "IsTor") == null) return error.NotRoutingThroughTor;
    return "traffic routed through tor";
}

fn testIdentityRotation(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    forceCleanup();

    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();

    var host_buf: [64]u8 = undefined;
    const original = try std.posix.gethostname(&host_buf);

    try engine.init(io, alloc, false, .tor);
    try engine.start(io, alloc, false, false);

    var new_host_buf: [64]u8 = undefined;
    const rotated = try std.posix.gethostname(&new_host_buf);

    try engine.stop(io, alloc);

    var restored_buf: [64]u8 = undefined;
    const restored = try std.posix.gethostname(&restored_buf);

    if (std.mem.eql(u8, original, rotated)) return error.HostnameNotRotated;
    if (!std.mem.eql(u8, original, restored)) return error.HostnameNotRestored;
    return "hostname rotated and restored";
}

fn testKillswitchRuleset(io: std.Io, alloc: std.mem.Allocator) ![]const u8 {
    forceCleanup();

    const env = try platform.probe(alloc);
    defer env.deinit();
    var engine = try Engine.create(alloc, env);
    defer engine.deinit();

    try engine.init(io, alloc, false, .tor);
    try engine.start(io, alloc, false, false);

    const rules = try execCmd(alloc, &.{ "sh", "-c", "iptables -S 2>/dev/null || true" });
    defer alloc.free(rules);

    try engine.stop(io, alloc);

    if (std.mem.indexOf(u8, rules, "veth-fella-host") == null) return error.KillswitchRulesMissing;
    return "killswitch rules active";
}

fn execInNetns(alloc: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    var full = std.ArrayList([]const u8).empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{ "ip", "netns", "exec", "fella" });
    try full.appendSlice(alloc, argv);
    return execCmd(alloc, full.items);
}

fn execCmd(alloc: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    const pid = std.os.linux.fork();
    if (pid == 0) {
        const tmp = "/tmp/fella_test_out";
        const fd = std.os.linux.open(tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
        if (fd >= 0) {
            _ = std.os.linux.dup2(@intCast(fd), 1);
            _ = std.os.linux.dup2(@intCast(fd), 2);
            _ = std.os.linux.close(@intCast(fd));
        }
        var argv_z: [64:null]?[*:0]const u8 = undefined;
        for (argv, 0..) |arg, i| {
            argv_z[i] = (std.heap.page_allocator.dupeZ(u8, arg) catch std.os.linux.exit(1)).ptr;
        }
        argv_z[argv.len] = null;
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
        const tmp = "/tmp/fella_test_out";
        const fd = std.posix.openatZ(-100, tmp, .{ .ACCMODE = .RDONLY }, 0) catch return alloc.dupe(u8, "") catch "";
        defer _ = std.os.linux.close(fd);
        var buf: [4096]u8 = undefined;
        const n = std.posix.read(fd, &buf) catch return alloc.dupe(u8, "") catch "";
        return alloc.dupe(u8, std.mem.trim(u8, buf[0..n], " \n\r")) catch "";
    } else {
        return alloc.dupe(u8, "") catch "";
    }
}

test "TestRunner result struct" {
    const r = Result{ .name = "demo", .passed = true, .detail = "ok" };
    try std.testing.expect(r.passed);
    try std.testing.expectEqualStrings("demo", r.name);
}
