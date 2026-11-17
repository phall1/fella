const std = @import("std");
const Io = std.Io;
const Session = @This();

/// The launch seam: resolved paths and policy in, an argv vector out.
/// No host mutations, shell interpolation, PID files, or transport plugins.
pub const Plan = struct {
    identity: []const u8,
    workspace_name: []const u8,
    home: []const u8,
    identity_etc: []const u8,
    project: []const u8,
    offline: bool,
    argv: []const []const u8,
    term: []const u8 = "xterm-256color",
};

pub const system_paths = [_][]const u8{
    "/usr",                 "/bin",             "/sbin",           "/lib",               "/lib64",
    "/etc/alternatives",    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",  "/etc/ssl",
    "/etc/ca-certificates", "/etc/resolv.conf", "/etc/hosts",      "/etc/nsswitch.conf", "/etc/localtime",
};

pub fn bubblewrap(io: Io) ![]const u8 {
    for ([_][]const u8{ "/usr/bin/bwrap", "/bin/bwrap" }) |candidate| {
        Io.Dir.accessAbsolute(io, candidate, .{}) catch continue;
        return candidate;
    }
    return error.BubblewrapNotFound;
}

pub fn availablePaths(arena: std.mem.Allocator, io: Io) ![]const []const u8 {
    var paths: std.ArrayList([]const u8) = .empty;
    for (system_paths) |path| {
        Io.Dir.accessAbsolute(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        try paths.append(arena, path);
    }
    return paths.items;
}

fn base(arena: std.mem.Allocator, bwrap: []const u8, paths: []const []const u8, offline: bool) !std.ArrayList([]const u8) {
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(arena, &.{
        bwrap,           "--die-with-parent", "--unshare-user", "--unshare-pid",
        "--unshare-ipc", "--unshare-uts",     "--cap-drop",     "ALL",
        "--clearenv",    "--uid",             "1000",           "--gid",
        "1000",
    });
    if (offline) try args.append(arena, "--unshare-net");
    for (paths) |path| try args.appendSlice(arena, &.{ "--ro-bind", path, path });
    try args.appendSlice(arena, &.{
        "--proc", "/proc", "--dev", "/dev",       "--tmpfs", "/tmp", "--tmpfs", "/run",
        "--dir",  "/home", "--dir", "/workspace",
    });
    return args;
}

pub fn build(arena: std.mem.Allocator, bwrap: []const u8, paths: []const []const u8, plan: Plan) ![]const []const u8 {
    var args = try base(arena, bwrap, paths, plan.offline);
    try args.appendSlice(arena, &.{
        "--ro-bind", try std.fs.path.join(arena, &.{ plan.identity_etc, "passwd" }), "/etc/passwd",
        "--ro-bind", try std.fs.path.join(arena, &.{ plan.identity_etc, "group" }),  "/etc/group",
        "--bind",    plan.home,                                                      "/home/fella",
        "--bind",    plan.project,                                                   "/workspace",
        "--chdir",   "/workspace",
    });
    try addEnvironment(arena, &args, plan);
    try args.append(arena, "--");
    if (plan.argv.len == 0) {
        try args.appendSlice(arena, &.{ "/bin/bash", "--noprofile", "-i" });
    } else {
        try args.appendSlice(arena, plan.argv);
    }
    return args.items;
}

fn addEnvironment(arena: std.mem.Allocator, args: *std.ArrayList([]const u8), plan: Plan) !void {
    const env = .{
        .{ "HOME", "/home/fella" },                                                                                     .{ "USER", "fella" },                          .{ "LOGNAME", "fella" },
        .{ "PATH", "/home/fella/.local/bin:/usr/local/bin:/usr/bin:/bin" },                                             .{ "SHELL", "/bin/bash" },                     .{ "LANG", "C.UTF-8" },
        .{ "TERM", plan.term },                                                                                         .{ "XDG_CONFIG_HOME", "/home/fella/.config" }, .{ "XDG_DATA_HOME", "/home/fella/.local/share" },
        .{ "XDG_STATE_HOME", "/home/fella/.local/state" },                                                              .{ "XDG_CACHE_HOME", "/home/fella/.cache" },   .{ "XDG_RUNTIME_DIR", "/run/fella" },
        .{ "FELLA_IDENTITY", plan.identity },                                                                           .{ "FELLA_WORKSPACE", plan.workspace_name },   .{ "FELLA_NETWORK", if (plan.offline) "offline" else "host" },
        .{ "PS1", try std.fmt.allocPrint(arena, "[fella:{s}/{s}] \\w \\$ ", .{ plan.identity, plan.workspace_name }) },
    };
    try args.appendSlice(arena, &.{ "--perms", "0700", "--dir", "/run/fella" });
    inline for (env) |pair| try args.appendSlice(arena, &.{ "--setenv", pair[0], pair[1] });
}

pub fn probe(arena: std.mem.Allocator, io: Io) !std.process.Child.Term {
    var args = try base(arena, try bubblewrap(io), try availablePaths(arena, io), true);
    try args.appendSlice(arena, &.{ "--", "/usr/bin/true" });
    var empty = std.process.Environ.Map.init(arena);
    defer empty.deinit();
    try protectInheritedFiles();
    var child = try std.process.spawn(io, .{ .argv = args.items, .environ_map = &empty });
    return child.wait(io);
}

/// Replace only after removing ambient environment and inherited file access.
pub fn execute(arena: std.mem.Allocator, io: Io, argv: []const []const u8) !u8 {
    var empty = std.process.Environ.Map.init(arena);
    try protectInheritedFiles();
    return std.process.replace(io, .{ .argv = argv, .environ_map = &empty });
}

fn protectInheritedFiles() !void {
    // Keep stdio, but do not smuggle host files/sockets through the sandbox.
    // CLOEXEC preserves Zig's own I/O descriptors until process replacement.
    // Closing them immediately would invalidate the runtime doing the exec.
    const result = std.os.linux.close_range(3, -1, .{ .UNSHARE = false, .CLOEXEC = true });
    if (result != 0) return error.DescriptorIsolationUnavailable;
}

test "plan uses only explicit mounts and arguments, never a shell wrapper" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const args = try build(arena.allocator(), "/usr/bin/bwrap", &.{"/usr"}, .{
        .identity = "work",
        .workspace_name = "project",
        .home = "/data/a b/home",
        .identity_etc = "/data/a b/etc",
        .project = "/code/a'b",
        .offline = false,
        .argv = &.{ "printf", "%s", "$(touch /tmp/escape)" },
    });
    try std.testing.expectEqualStrings("$(touch /tmp/escape)", args[args.len - 1]);
    try std.testing.expect(!hasArg(args, "/"));
    try std.testing.expect(!hasArg(args, "--unshare-net"));
    try std.testing.expect(hasArg(args, "--clearenv"));
    try std.testing.expect(hasArg(args, "/code/a'b"));
    try std.testing.expect(!hasArg(args, "-c"));
}

fn hasArg(args: []const []const u8, needle: []const u8) bool {
    for (args) |arg| if (std.mem.eql(u8, arg, needle)) return true;
    return false;
}

test "offline is an enforced namespace and shell is identity-local" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const args = try build(arena.allocator(), "/usr/bin/bwrap", &.{}, .{
        .identity = "personal",
        .workspace_name = "notes",
        .home = "/data/home",
        .identity_etc = "/data/etc",
        .project = "/code",
        .offline = true,
        .argv = &.{},
    });
    try std.testing.expect(hasArg(args, "--unshare-net"));
    try std.testing.expect(hasArg(args, "--noprofile"));
    try std.testing.expect(hasArg(args, "--unshare-pid"));
    try std.testing.expect(!hasArg(args, "--ro-bind-try"));
}
