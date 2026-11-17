const std = @import("std");
const builtin = @import("builtin");
const Cli = @import("Cli.zig");
const Store = @import("Store.zig");
const Session = @import("Session.zig");
const Io = std.Io;

const help =
    \\fella — contained Linux workspaces, without a daemon or sudo
    \\
    \\  fella identity create <name>       Create a separate persistent home
    \\  fella identity list                List identities
    \\  fella identity path <name>         Print identity home for setup/backups
    \\  fella workspace add <name> --identity <name> --path <directory>
    \\  fella workspace list               List registered workspaces
    \\  fella workspace remove <name>      Forget registration; never delete data
    \\  fella show <workspace>             Show identity, paths, network policy
    \\  fella enter <workspace> [--offline] [-- <command> [args...]]
    \\  fella doctor                       Test real Linux isolation support
    \\  fella help | version
    \\
    \\Networking is shared with the host unless --offline is specified.
    \\Only the selected identity home and project are writable host mounts.
    \\No host credentials, SSH agent, desktop bus, or display are inherited.
    \\Exit the shell to end the session. Homes and projects persist.
    \\Launcher signals/direct-command Ctrl-C can hard-stop unsaved applications.
    \\
;

pub fn main(init: std.process.Init) void {
    const code = run(init) catch |err| {
        report(init.io, err) catch {};
        std.process.exit(1);
    };
    if (code != 0) std.process.exit(code);
}

fn run(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const command = try Cli.parse(try arguments(init));
    switch (command) {
        .help => return output(init.io, help),
        .version => return print(init, "fella 0.7.0 (Zig {s})\n", .{builtin.zig_version_string}),
        else => {},
    }
    try requireLinuxUser();
    if (command == .doctor) return doctor(arena, init.io);
    const home = init.environ_map.get("HOME") orelse return error.InvalidHome;
    const store: Store = .{
        .io = init.io,
        .arena = arena,
        .root = try Store.dataRoot(arena, home, init.environ_map.get("XDG_DATA_HOME")),
    };
    return dispatch(init, store, home, command);
}

fn arguments(init: std.process.Init) ![]const []const u8 {
    const arena = init.arena.allocator();
    var iter = try init.minimal.args.iterateAllocator(arena);
    var args: std.ArrayList([]const u8) = .empty;
    _ = iter.next();
    while (iter.next()) |arg| try args.append(arena, arg);
    return args.items;
}

fn requireLinuxUser() !void {
    if (builtin.os.tag != .linux) return error.LinuxRequired;
    if (std.c.getuid() == 0 or std.c.geteuid() == 0) return error.RootNotSupported;
}

fn dispatch(init: std.process.Init, store: Store, home: []const u8, command: Cli.Command) !u8 {
    switch (command) {
        .identity_create => |name| return createIdentity(init, store, name),
        .identity_path => |name| return identityPath(init, store, name),
        .identity_list => return list(init, store, .identities),
        .workspace_list => return list(init, store, .workspaces),
        .workspace_add => |add| return addWorkspace(init, store, home, add),
        .workspace_remove => |name| return removeWorkspace(init, store, name),
        .show => |name| return show(init, store, name),
        .enter => |enter| return launch(init, store, home, enter),
        else => unreachable,
    }
}

fn createIdentity(init: std.process.Init, store: Store, name: []const u8) !u8 {
    try store.createIdentity(name);
    return print(init, "Created identity {s}\n", .{name});
}

fn identityPath(init: std.process.Init, store: Store, name: []const u8) !u8 {
    return print(init, "{s}\n", .{try store.identityHome(name)});
}

fn addWorkspace(init: std.process.Init, store: Store, home: []const u8, add: Cli.Add) !u8 {
    try store.addWorkspace(add.name, add.identity, add.path, home);
    return print(init, "Registered {s} with identity {s}\n", .{ add.name, add.identity });
}

fn removeWorkspace(init: std.process.Init, store: Store, name: []const u8) !u8 {
    try store.removeWorkspace(name);
    return output(init.io, "Registration removed; project and identity data kept.\n");
}

fn list(init: std.process.Init, store: Store, kind: Store.Kind) !u8 {
    const names = try store.names(kind);
    for (names) |name| _ = try print(init, "{s}\n", .{name});
    return 0;
}

fn show(init: std.process.Init, store: Store, name: []const u8) !u8 {
    const workspace = try store.loadWorkspace(name);
    return print(init, "Workspace: {s}\nIdentity:  {s}\nProject:   {s}\nHome:      {s}\nNetwork:   host (use enter --offline to disconnect)\n", .{
        name, workspace.identity, workspace.path, try store.identityHome(workspace.identity),
    });
}

fn launch(init: std.process.Init, store: Store, host_home: []const u8, enter: Cli.Enter) !u8 {
    const arena = store.arena;
    const bwrap = try Session.bubblewrap(init.io);
    const workspace = try store.loadWorkspace(enter.name);
    // Resolve again: a moved project or symlink must not broaden a saved grant.
    const project = try store.resolveProject(workspace.path, host_home);
    if (!std.mem.eql(u8, project, workspace.path)) return error.WorkspaceMoved;
    const args = try Session.build(arena, bwrap, try Session.availablePaths(arena, init.io), .{
        .identity = workspace.identity,
        .workspace_name = enter.name,
        .home = try store.identityHome(workspace.identity),
        .identity_etc = try store.identityEtc(workspace.identity),
        .project = project,
        .offline = enter.offline,
        .argv = enter.argv,
        .term = init.environ_map.get("TERM") orelse "xterm-256color",
    });
    // Replace, don't supervise: bwrap owns the PID namespace and exit status.
    return Session.execute(arena, init.io, args);
}

fn doctor(arena: std.mem.Allocator, io: Io) !u8 {
    Io.Dir.accessAbsolute(io, "/bin/bash", .{}) catch return error.BashNotFound;
    _ = try output(io, "Checking bubblewrap, user/PID/mount/network namespaces...\n");
    const term = try Session.probe(arena, io);
    if (!term.success()) return error.IsolationUnavailable;
    return output(io, "Ready. Sessions need no root and make no host-wide changes.\n");
}

fn output(io: Io, text: []const u8) !u8 {
    try Io.File.stdout().writeStreamingAll(io, text);
    return 0;
}

fn print(init: std.process.Init, comptime fmt: []const u8, args: anytype) !u8 {
    return output(init.io, try std.fmt.allocPrint(init.arena.allocator(), fmt, args));
}

fn report(io: Io, err: anyerror) !void {
    const hints = .{
        .{ error.BubblewrapNotFound, "Install bubblewrap with your distribution's package manager." },
        .{ error.BashNotFound, "Install bash with your distribution's package manager." },
        .{ error.IsolationUnavailable, "Linux isolation is unavailable. Check user namespaces/AppArmor; there is no unsandboxed fallback." },
        .{ error.DescriptorIsolationUnavailable, "File-descriptor isolation requires Linux 5.11+ and permitted close_range(CLOEXEC)." },
        .{ error.RootNotSupported, "Run as your normal user, not through sudo." },
        .{ error.LinuxRequired, "Sessions require Linux. Builds/unit tests can run on macOS." },
        .{ error.InvalidArguments, "Invalid arguments. See 'fella help'." },
        .{ error.UnknownCommand, "Unknown command. See 'fella help'." },
        .{ error.InvalidName, "Names must be 1–48 letters, numbers, hyphens or underscores." },
        .{ error.InvalidHome, "HOME must name an existing absolute home directory." },
        .{ error.InvalidDataHome, "XDG_DATA_HOME must be an absolute directory path." },
        .{ error.IdentityNotFound, "Create the identity first with 'fella identity create <name>'." },
        .{ error.WorkspaceNotFound, "Register the workspace first with 'fella workspace add'." },
        .{ error.UnsafeWorkspacePath, "Select a project directory, not a host tree, entire home, or fella data directory." },
        .{ error.WorkspaceMoved, "The project path changed through a symlink. Remove and re-register the workspace." },
        .{ error.InsecureDataDirectory, "Fella's data directory must be private (mode 0700)." },
        .{ error.PathAlreadyExists, "That name already exists; existing data was not replaced." },
    };
    var buffer: [1024]u8 = undefined;
    var text: []const u8 = "Check paths and permissions; no unsandboxed fallback was used.";
    inline for (hints) |hint| {
        if (err == hint[0]) text = hint[1];
    }
    const message = try std.fmt.bufPrint(&buffer, "fella: {s}: {s}\n", .{ @errorName(err), text });
    try Io.File.stderr().writeStreamingAll(io, message);
}

test {
    _ = Cli;
    _ = Store;
    _ = Session;
}
