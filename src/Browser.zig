const std = @import("std");
const Output = @import("Output.zig");

const PROFILE_PREFIX = "/tmp/fella-firefox-";
const USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Launch an ephemeral Firefox profile inside the fella netns with
/// anti-fingerprinting hardening and SOCKS5 proxy configured.
pub fn launch(io: std.Io, alloc: std.mem.Allocator, locale: []const u8) !void {
    if (!hasBinary("firefox")) {
        try Output.stdoutPrint(io, alloc, "{s}[!] firefox not found. Install it first.{s}\n", .{ Output.Color.red, Output.Color.reset });
        return error.FirefoxNotFound;
    }

    if (!netnsExists()) {
        try Output.stdoutPrint(io, alloc, "{s}[!] No active fella namespace. Run 'fella start' first.{s}\n", .{ Output.Color.red, Output.Color.reset });
        return error.NetnsNotFound;
    }

    try Output.stdoutPrint(io, alloc, "[+] Generating ephemeral Firefox profile...\n", .{});

    const profile_dir = try createProfileDir(alloc);
    defer alloc.free(profile_dir);

    try writeUserJs(profile_dir, locale);

    try Output.stdoutPrint(io, alloc, "{s}[+] Launching Firefox in fella namespace{s}\n", .{ Output.Color.blue, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "    [*] Profile: {s}\n", .{profile_dir});
    try Output.stdoutPrint(io, alloc, "    [*] WebRTC: disabled | WebGL: disabled | RFP: on\n", .{});

    // Launch firefox inside netns with private mount namespace + resolv.conf bind-mount
    const has_unshare = hasBinary("unshare");
    var cmd_inner: std.ArrayList(u8) = .empty;
    defer cmd_inner.deinit(alloc);

    if (has_unshare) {
        try cmd_inner.appendSlice(alloc, "mount --bind /var/lib/fella/resolv.conf /etc/resolv.conf && ");
    }
    try cmd_inner.appendSlice(alloc, "exec firefox -profile '");
    try cmd_inner.appendSlice(alloc, profile_dir);
    try cmd_inner.appendSlice(alloc, "' -no-remote -new-instance");

    var full_argv: std.ArrayList([]const u8) = .empty;
    defer full_argv.deinit(alloc);

    if (has_unshare) {
        try full_argv.appendSlice(alloc, &.{
            "ip", "netns", "exec", "fella",
            "unshare", "-m",
            "sh", "-c",
        });
    } else {
        try full_argv.appendSlice(alloc, &.{
            "ip", "netns", "exec", "fella",
            "sh", "-c",
        });
    }
    try full_argv.append(alloc, cmd_inner.items);

    try runCmdArgv(full_argv.items);

    // Best-effort cleanup after Firefox exits
    try Output.stdoutPrint(io, alloc, "[+] Wiping ephemeral profile...\n", .{});
    wipeProfileDir(profile_dir) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Profile cleanup failed: {any}\n", .{err});
    };
}

fn createProfileDir(alloc: std.mem.Allocator) ![]const u8 {
    var seed_buf: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_buf, seed_buf.len, 0);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var buf: [64]u8 = undefined;
    const suffix = std.fmt.bufPrint(&buf, "{x:0>8}", .{rand.int(u32)}) catch "00000000";

    const dir = try std.fmt.allocPrint(alloc, "{s}{s}", .{ PROFILE_PREFIX, suffix });
    errdefer alloc.free(dir);

    var dir_z: [128:0]u8 = undefined;
    @memcpy(dir_z[0..dir.len], dir);
    dir_z[dir.len] = 0;
    const rc = std.os.linux.mkdir(&dir_z, 0o700);
    if (rc != 0 and std.posix.errno(rc) != .EXIST) return error.MkdirFailed;

    return dir;
}

fn writeUserJs(profile_dir: []const u8, locale: []const u8) !void {
    var path_buf: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/user.js", .{profile_dir});

    var js_buf: [4096]u8 = undefined;
    const js = std.fmt.bufPrint(&js_buf,
        \\// fella ephemeral profile — generated automatically
        \\user_pref("privacy.resistFingerprinting", true);
        \\user_pref("media.peerconnection.enabled", false);
        \\user_pref("webgl.disabled", true);
        \\user_pref("canvas.capturestream.enabled", false);
        \\user_pref("browser.cache.disk.enable", false);
        \\user_pref("browser.sessionstore.resume_from_crash", false);
        \\user_pref("browser.tabs.firefox-view", false);
        \\user_pref("places.history.enabled", false);
        \\user_pref("browser.download.start_downloads_in_tmp_dir", true);
        \\user_pref("browser.download.folderList", 0);
        \\user_pref("network.proxy.type", 1);
        \\user_pref("network.proxy.socks", "10.200.200.1");
        \\user_pref("network.proxy.socks_port", 9050);
        \\user_pref("network.proxy.socks_remote_dns", true);
        \\user_pref("network.proxy.no_proxies_on", "");
        \\user_pref("general.useragent.override", "{s}");
        \\user_pref("intl.accept_languages", "{s}");
        \\user_pref("privacy.trackingprotection.enabled", true);
        \\user_pref("dom.battery.enabled", false);
        \\user_pref("dom.netinfo.enabled", false);
        \\user_pref("geo.enabled", false);
        \\user_pref("browser.safebrowsing.enabled", false);
        \\user_pref("browser.safebrowsing.malware.enabled", false);
        \\user_pref("extensions.pocket.enabled", false);
        \\user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
        \\user_pref("browser.newtabpage.activity-stream.telemetry", false);
        \\user_pref("toolkit.telemetry.enabled", false);
        \\user_pref("toolkit.telemetry.unified", false);
        \\user_pref("datareporting.healthreport.uploadEnabled", false);
        \\user_pref("datareporting.policy.dataSubmissionEnabled", false);
        \\user_pref("browser.startup.homepage", "about:blank");
        \\user_pref("browser.newtabpage.enabled", false);
        \\
    , .{ USER_AGENT, locale }) catch return error.BufTooSmall;

    try writeFileZ(path, js);
}

fn wipeProfileDir(dir: []const u8) !void {
    var dir_z: [512:0]u8 = undefined;
    @memcpy(dir_z[0..dir.len], dir);
    dir_z[dir.len] = 0;

    // Try recursive delete via rm -rf first
    var rm_argv: [64:null]?[*:0]const u8 = undefined;
    @memset(&rm_argv, null);
    rm_argv[0] = "rm";
    rm_argv[1] = "-rf";
    rm_argv[2] = &dir_z;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve("/bin/rm", &rm_argv, @ptrCast(std.c.environ));
        _ = std.os.linux.execve("/usr/bin/rm", &rm_argv, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var status: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &status, 0);
    }
}

fn netnsExists() bool {
    const fd = std.posix.openatZ(-100, "/run/netns/fella", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = std.os.linux.close(fd);
    return true;
}

fn hasBinary(name: []const u8) bool {
    const prefixes = [_][]const u8{ "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/" };
    var buf: [128:0]u8 = undefined;
    for (prefixes) |prefix| {
        const path = std.fmt.bufPrint(&buf, "{s}{s}", .{ prefix, name }) catch continue;
        buf[path.len] = 0;
        if (std.os.linux.access(&buf, 0) == 0) return true;
    }
    return false;
}

fn runCmdArgv(argv: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = arena_alloc.dupeZ(u8, arg) catch return error.CmdFailed;
    }

    const cmd = resolveCmd(argv[0], arena_alloc) orelse return error.CmdNotFound;
    argv_z[0] = cmd;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var wstatus: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &wstatus, 0);
    } else {
        return error.ForkFailed;
    }
}

fn resolveCmd(name: []const u8, arena_alloc: std.mem.Allocator) ?[*:0]const u8 {
    if (name[0] == '/') return arena_alloc.dupeZ(u8, name) catch null;
    const prefixes = [_][]const u8{ "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/" };
    for (prefixes) |prefix| {
        const path = std.fs.path.join(arena_alloc, &.{ prefix, name }) catch continue;
        const path_z = arena_alloc.dupeZ(u8, path) catch continue;
        if (std.os.linux.access(path_z, 0) == 0) {
            return path_z;
        }
    }
    return null;
}

fn writeFileZ(path: []const u8, data: []const u8) !void {
    var path_z: [512:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = try std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}
