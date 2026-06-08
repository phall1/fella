const std = @import("std");
const Output = @import("Output.zig");

const NS_NAME = "fella";
const VETH_HOST = "veth-fella-host";
const VETH_NS = "veth-fella-ns";
const HOST_IP = "10.200.200.1";
const NS_IP = "10.200.200.2";
const SUBNET = "10.200.200.0/30";

const TORSOCKS_CONF =
    \\TorAddress {s}
    \\TorPort 9050
    \\
    ;

const RESOLV_CONF =
    \\# fella — all DNS forced through Tor DNSPort
    \\nameserver {s}
    \\options timeout:5 attempts:2 rotate
    \\
    ;

pub fn create(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Creating network namespace...\n", .{});

    // Clean up any stale state (silently — stale state is expected)
    destroyQuiet();

    // Create netns
    try runIp(alloc, &.{ "netns", "add", NS_NAME });

    // Create veth pair
    try runIp(alloc, &.{ "link", "add", VETH_HOST, "type", "veth", "peer", "name", VETH_NS });

    // Move netns end into namespace
    try runIp(alloc, &.{ "link", "set", VETH_NS, "netns", NS_NAME });

    // Configure host side
    try runIp(alloc, &.{ "addr", "add", HOST_IP ++ "/30", "dev", VETH_HOST });
    try runIp(alloc, &.{ "link", "set", VETH_HOST, "up" });

    // Configure netns side
    try runIpNs(alloc, &.{ "addr", "add", NS_IP ++ "/30", "dev", VETH_NS });
    try runIpNs(alloc, &.{ "link", "set", "lo", "up" });
    try runIpNs(alloc, &.{ "link", "set", VETH_NS, "up" });

    // Enable IP forwarding on host
    {
        const fd = std.os.linux.open("/proc/sys/net/ipv4/ip_forward", .{ .ACCMODE = .WRONLY }, 0);
        if (fd >= 0) {
            _ = std.os.linux.write(@intCast(fd), "1\n", 2);
            _ = std.os.linux.close(@intCast(fd));
        }
    }

    // Host NAT for netns traffic
    try runIptables(alloc, &.{ "-t", "nat", "-A", "POSTROUTING", "-s", SUBNET, "-j", "MASQUERADE" });

    // Default route inside netns so non-torsocks apps can at least attempt routing
    runIpNs(alloc, &.{ "route", "add", "default", "via", HOST_IP, "dev", VETH_NS }) catch {
        // May already exist on re-create; ignore
    };

    // Netns firewall: drop everything by default, only allow Tor/DNS to host
    try runIptablesNs(alloc, &.{ "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT" });
    try runIptablesNs(alloc, &.{ "-A", "OUTPUT", "-p", "tcp", "-d", HOST_IP, "--dport", "9050", "-j", "ACCEPT" });
    try runIptablesNs(alloc, &.{ "-A", "OUTPUT", "-p", "tcp", "-d", HOST_IP, "--dport", "9051", "-j", "ACCEPT" });
    try runIptablesNs(alloc, &.{ "-A", "OUTPUT", "-p", "udp", "-d", HOST_IP, "--dport", "5353", "-j", "ACCEPT" });
    try runIptablesNs(alloc, &.{ "-P", "OUTPUT", "DROP" });

    // Write torsocks config
    var torsocks_buf: [256]u8 = undefined;
    const torsocks_conf = std.fmt.bufPrint(&torsocks_buf, TORSOCKS_CONF, .{HOST_IP}) catch TORSOCKS_CONF;
    try writeFileZ("/var/lib/fella/torsocks.conf", torsocks_conf);

    // Write netns resolv.conf for DNS enforcement
    var resolv_buf: [256]u8 = undefined;
    const resolv_conf = std.fmt.bufPrint(&resolv_buf, RESOLV_CONF, .{HOST_IP}) catch "nameserver 10.200.200.1\n";
    try writeFileZ("/var/lib/fella/resolv.conf", resolv_conf);

    // Disable IPv6 inside netns to prevent AAAA leaks
    disableIPv6InNs(alloc) catch |err| {
        try Output.stdoutPrint(io, alloc, "    [!] Could not disable IPv6 in netns: {any}\n", .{err});
    };

    try Output.stdoutPrint(io, alloc, "    [+] Namespace {s} ready ({s} ↔ {s})\n", .{ NS_NAME, HOST_IP, NS_IP });
}

pub fn destroy(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "[+] Destroying network namespace...\n", .{});
    destroyQuiet();
    try Output.stdoutPrint(io, alloc, "    [+] Namespace removed\n", .{});
}

pub fn destroyQuiet() void {
    _ = runCmdSilent(&.{ "iptables", "-t", "nat", "-D", "POSTROUTING", "-s", SUBNET, "-j", "MASQUERADE" });
    _ = runCmdSilent(&.{ "ip", "link", "del", VETH_HOST });
    _ = runCmdSilent(&.{ "ip", "netns", "del", NS_NAME });
}

fn netnsExists() bool {
    const fd = std.posix.openatZ(-100, "/run/netns/fella", .{ .ACCMODE = .RDONLY }, 0) catch return false;
    _ = std.os.linux.close(fd);
    return true;
}

pub fn execNs(io: std.Io, alloc: std.mem.Allocator, argv: []const []const u8) !void {
    if (!netnsExists()) {
        try Output.stdoutPrint(io, alloc, "{s}[!] No active fella namespace. Run 'fella start' first.{s}\n", .{ Output.Color.red, Output.Color.reset });
        return error.NetnsNotFound;
    }

    // Warn about LD_PRELOAD limitation
    if (argv.len > 0) {
        const bin_name = std.fs.path.basename(argv[0]);
        if (isLikelyStaticBinary(bin_name)) {
            try Output.stdoutPrint(io, alloc, "{s}[!] Warning: {s} may be statically linked. torsocks LD_PRELOAD will not work.{s}\n", .{ Output.Color.yellow, bin_name, Output.Color.reset });
            try Output.stdoutPrint(io, alloc, "    [*] Configure the app to use SOCKS5 proxy 10.200.200.1:9050 directly\n", .{});
        }
    }

    var full_argv: std.ArrayList([]const u8) = .empty;
    defer full_argv.deinit(alloc);

    const has_unshare = hasBinary("unshare");
    if (has_unshare) {
        // Enter netns + private mount namespace, bind-mount resolv.conf, then torsocks
        try full_argv.appendSlice(alloc, &.{
            "ip", "netns", "exec", NS_NAME,
            "unshare", "-m",
            "sh", "-c",
        });
        var cmd_inner: std.ArrayList(u8) = .empty;
        defer cmd_inner.deinit(alloc);
        try cmd_inner.appendSlice(alloc, "mount --bind /var/lib/fella/resolv.conf /etc/resolv.conf && export TORSOCKS_CONF_FILE=/var/lib/fella/torsocks.conf && exec /usr/bin/torsocks ");
        for (argv) |arg| {
            try cmd_inner.append(alloc, '\'');
            try cmd_inner.appendSlice(alloc, arg);
            try cmd_inner.appendSlice(alloc, "'\''");
            try cmd_inner.append(alloc, ' ');
        }
        try full_argv.append(alloc, cmd_inner.items);
    } else {
        try Output.stdoutPrint(io, alloc, "    [!] 'unshare' not found — DNS may leak\n", .{});
        try full_argv.appendSlice(alloc, &.{
            "ip", "netns", "exec", NS_NAME,
            "/usr/bin/env", "TORSOCKS_CONF_FILE=/var/lib/fella/torsocks.conf",
            "/usr/bin/torsocks",
        });
        for (argv) |arg| {
            try full_argv.append(alloc, arg);
        }
    }

    try runCmdArgv(full_argv.items);
}

fn isLikelyStaticBinary(name: []const u8) bool {
    // Common statically-linked binaries that bypass LD_PRELOAD
    const static_bins = [_][]const u8{ "go", "terraform", "kubectl", "docker" };
    for (static_bins) |s| {
        if (std.mem.eql(u8, name, s)) return true;
    }
    return false;
}

pub fn shell(io: std.Io, alloc: std.mem.Allocator) !void {
    if (!netnsExists()) {
        try Output.stdoutPrint(io, alloc, "{s}[!] No active fella namespace. Run 'fella start' first.{s}\n", .{ Output.Color.red, Output.Color.reset });
        return error.NetnsNotFound;
    }
    try Output.stdoutPrint(io, alloc, "{s}[+] Dropping into fella shell (Tor-routed namespace){s}\n", .{ Output.Color.blue, Output.Color.reset });
    try Output.stdoutPrint(io, alloc, "    Type 'exit' to return\n", .{});

    const has_unshare = hasBinary("unshare");
    if (!has_unshare) {
        try Output.stdoutPrint(io, alloc, "    [!] 'unshare' not found — DNS may leak in shell\n", .{});
    }

    const script = if (has_unshare)
        "#!/bin/sh\nexport TORSOCKS_CONF_FILE=\"/var/lib/fella/torsocks.conf\"\nexec unshare -m sh -c 'mount --bind /var/lib/fella/resolv.conf /etc/resolv.conf && exec /usr/bin/torsocks \"${SHELL:-/bin/bash}\" -i'\n"
    else
        "#!/bin/sh\nexport TORSOCKS_CONF_FILE=\"/var/lib/fella/torsocks.conf\"\nexec /usr/bin/torsocks \"${SHELL:-/bin/bash}\" -i\n";

    const cmd = "/tmp/fella_shell.sh";
    _ = std.os.linux.unlink(cmd);

    var path_z: [256:0]u8 = undefined;
    @memcpy(path_z[0..cmd.len], cmd);
    path_z[cmd.len] = 0;

    const fd = std.os.linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o700);
    if (fd >= 0) {
        _ = std.os.linux.write(@intCast(fd), script.ptr, script.len);
        _ = std.os.linux.close(@intCast(fd));
    }

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    argv_z[0] = "ip";
    argv_z[1] = "netns";
    argv_z[2] = "exec";
    argv_z[3] = NS_NAME;
    argv_z[4] = "sh";
    argv_z[5] = cmd;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve("/usr/sbin/ip", &argv_z, @ptrCast(std.c.environ));
        _ = std.os.linux.execve("/sbin/ip", &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var wstatus: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &wstatus, 0);
    } else {
        return error.ForkFailed;
    }
}

fn runIp(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{"ip"});
    for (args) |a| try full.append(alloc, a);
    try runCmdArgv(full.items);
}

fn runIpNs(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{ "ip", "netns", "exec", NS_NAME, "ip" });
    for (args) |a| try full.append(alloc, a);
    try runCmdArgv(full.items);
}

fn runIptables(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{"iptables"});
    for (args) |a| try full.append(alloc, a);
    try runCmdArgv(full.items);
}

fn runIptablesNs(alloc: std.mem.Allocator, args: []const []const u8) !void {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{ "ip", "netns", "exec", NS_NAME, "iptables" });
    for (args) |a| try full.append(alloc, a);
    try runCmdArgv(full.items);
}

fn disableIPv6InNs(alloc: std.mem.Allocator) !void {
    var full: std.ArrayList([]const u8) = .empty;
    defer full.deinit(alloc);
    try full.appendSlice(alloc, &.{ "ip", "netns", "exec", NS_NAME, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1" });
    try runCmdArgv(full.items);
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

fn runCmd(argv: []const []const u8) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = arena_alloc.dupeZ(u8, arg) catch return -1;
    }

    const cmd = resolveCmd(argv[0], arena_alloc) orelse return -1;
    argv_z[0] = cmd;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var wstatus: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &wstatus, 0);
        return @intCast(wstatus);
    } else {
        return -1;
    }
}

fn runCmdSilent(argv: []const []const u8) i32 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var argv_z: [64:null]?[*:0]const u8 = undefined;
    @memset(&argv_z, null);
    for (argv, 0..) |arg, i| {
        argv_z[i] = arena_alloc.dupeZ(u8, arg) catch return -1;
    }

    const cmd = resolveCmd(argv[0], arena_alloc) orelse return -1;
    argv_z[0] = cmd;

    const pid = std.os.linux.fork();
    if (pid == 0) {
        // Redirect stderr to /dev/null so cleanup commands are quiet
        _ = std.os.linux.close(2);
        var devnull: [16:0]u8 = undefined;
        @memcpy(devnull[0..9], "/dev/null");
        devnull[9] = 0;
        _ = std.os.linux.open(&devnull, .{ .ACCMODE = .WRONLY }, 0);
        _ = std.os.linux.execve(argv_z[0].?, &argv_z, @ptrCast(std.c.environ));
        std.os.linux.exit(1);
    } else if (pid > 0) {
        var wstatus: u32 = 0;
        _ = std.os.linux.waitpid(@intCast(pid), &wstatus, 0);
        return @intCast(wstatus);
    } else {
        return -1;
    }
}

fn runCmdArgv(argv: []const []const u8) !void {
    const rc = runCmd(argv);
    if (rc != 0) return error.CmdFailed;
}

fn writeFileZ(path: []const u8, data: []const u8) !void {
    var path_z: [512:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;
    const fd = try std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    defer _ = std.os.linux.close(fd);
    _ = std.os.linux.write(fd, data.ptr, data.len);
}
