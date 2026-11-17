const std = @import("std");
const Cli = @import("Cli.zig");
const Io = std.Io;
const Dir = Io.Dir;
const Store = @This();

/// All returned strings live in the caller's arena. No session state is stored.
io: Io,
arena: std.mem.Allocator,
root: []const u8,

pub const Workspace = struct {
    version: u8 = 1,
    identity: []const u8,
    path: []const u8,
};

pub fn dataRoot(arena: std.mem.Allocator, home: []const u8, xdg: ?[]const u8) ![]const u8 {
    if (!std.fs.path.isAbsolute(home)) return error.InvalidHome;
    const base = xdg orelse "";
    if (base.len == 0) return std.fs.path.join(arena, &.{ home, ".local/share/fella" });
    if (!std.fs.path.isAbsolute(base)) return error.InvalidDataHome;
    return std.fs.path.join(arena, &.{ base, "fella" });
}

fn path(self: Store, parts: []const []const u8) ![]const u8 {
    const all = try self.arena.alloc([]const u8, parts.len + 1);
    all[0] = self.root;
    @memcpy(all[1..], parts);
    return std.fs.path.join(self.arena, all);
}

fn ensureRoot(self: Store) !void {
    _ = try Dir.cwd().createDirPathStatus(self.io, self.root, .fromMode(0o700));
    try self.checkRoot();
}

fn checkRoot(self: Store) !void {
    const dir = try Dir.openDirAbsolute(self.io, self.root, .{ .follow_symlinks = false });
    defer dir.close(self.io);
    const stat = try dir.stat(self.io);
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecureDataDirectory;
}

fn privateDir(self: Store, dir_path: []const u8) !void {
    _ = try Dir.cwd().createDirPathStatus(self.io, dir_path, .fromMode(0o700));
}

pub fn createIdentity(self: Store, name: []const u8) !void {
    if (!Cli.validName(name)) return error.InvalidName;
    try self.ensureRoot();
    try self.privateDir(try self.path(&.{"identities"}));
    const stage = try self.identityStage();
    errdefer Dir.cwd().deleteTree(self.io, stage) catch {};
    try self.initializeIdentity(stage);
    try Dir.cwd().renamePreserve(stage, .cwd(), try self.path(&.{ "identities", name }), self.io);
}

fn identityStage(self: Store) ![]const u8 {
    var random: [16]u8 = undefined;
    try self.io.randomSecure(&random);
    const name = try std.fmt.allocPrint(self.arena, ".creating-{s}", .{std.fmt.bytesToHex(random, .lower)});
    const stage = try self.path(&.{ "identities", name });
    try Dir.createDirAbsolute(self.io, stage, .fromMode(0o700));
    return stage;
}

fn initializeIdentity(self: Store, identity_dir: []const u8) !void {
    const dirs = [_][]const u8{ "home", "home/.config", "home/.local/bin", "home/.local/share", "home/.local/state", "home/.cache", "etc" };
    for (dirs) |dir| try self.privateDir(try std.fs.path.join(self.arena, &.{ identity_dir, dir }));
    try self.writeIdentityEtc(identity_dir);
    try self.writePrivate(try std.fs.path.join(self.arena, &.{ identity_dir, "ready" }), "1\n");
}

fn writeIdentityEtc(self: Store, identity_dir: []const u8) !void {
    // Fixed namespace-local IDs make homes portable across host user IDs.
    try self.writePrivate(try std.fs.path.join(self.arena, &.{ identity_dir, "etc/passwd" }), "root:x:0:0:root:/root:/bin/sh\nfella:x:1000:1000:fella:/home/fella:/bin/bash\n");
    try self.writePrivate(try std.fs.path.join(self.arena, &.{ identity_dir, "etc/group" }), "root:x:0:\nfella:x:1000:\n");
}

fn writePrivate(self: Store, file_path: []const u8, data: []const u8) !void {
    try Dir.cwd().writeFile(self.io, .{
        .sub_path = file_path,
        .data = data,
        .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
    });
}

pub fn identityHome(self: Store, name: []const u8) ![]const u8 {
    if (!Cli.validName(name)) return error.InvalidName;
    try self.checkRoot();
    const ready = try self.path(&.{ "identities", name, "ready" });
    var buf: [16]u8 = undefined;
    const version = Dir.cwd().readFile(self.io, ready, &buf) catch |err| switch (err) {
        error.FileNotFound => return error.IdentityNotFound,
        else => return err,
    };
    if (!std.mem.eql(u8, version, "1\n")) return error.InvalidIdentity;
    const home = try self.path(&.{ "identities", name, "home" });
    const dir = try Dir.openDirAbsolute(self.io, home, .{ .follow_symlinks = false });
    dir.close(self.io);
    return home;
}

pub fn identityEtc(self: Store, name: []const u8) ![]const u8 {
    _ = try self.identityHome(name);
    return self.path(&.{ "identities", name, "etc" });
}

pub fn addWorkspace(self: Store, name: []const u8, identity: []const u8, project: []const u8, host_home: []const u8) !void {
    if (!Cli.validName(name)) return error.InvalidName;
    _ = try self.identityHome(identity);
    const canonical = try self.resolveProject(project, host_home);
    try self.publishWorkspace(name, .{ .identity = identity, .path = canonical });
}

pub fn resolveProject(self: Store, project: []const u8, host_home: []const u8) ![]const u8 {
    const canonical = try Dir.cwd().realPathFileAlloc(self.io, project, self.arena);
    const dir = try Dir.openDirAbsolute(self.io, canonical, .{});
    dir.close(self.io);
    const real_home = try Dir.cwd().realPathFileAlloc(self.io, host_home, self.arena);
    const real_root = try Dir.cwd().realPathFileAlloc(self.io, self.root, self.arena);
    try checkWorkspacePath(canonical, real_home, real_root);
    return canonical;
}

fn publishWorkspace(self: Store, name: []const u8, workspace: Workspace) !void {
    try self.privateDir(try self.path(&.{"workspaces"}));
    const bytes = try std.json.Stringify.valueAlloc(self.arena, workspace, .{});
    var atomic = try Dir.cwd().createFileAtomic(self.io, try self.workspaceFile(name), .{ .permissions = .fromMode(0o600) });
    defer atomic.deinit(self.io);
    try atomic.file.writeStreamingAll(self.io, bytes);
    try atomic.file.sync(self.io);
    try atomic.link(self.io);
}

fn workspaceFile(self: Store, name: []const u8) ![]const u8 {
    if (!Cli.validName(name)) return error.InvalidName;
    return self.path(&.{ "workspaces", try std.fmt.allocPrint(self.arena, "{s}.json", .{name}) });
}

pub fn loadWorkspace(self: Store, name: []const u8) !Workspace {
    try self.checkRoot();
    const bytes = Dir.cwd().readFileAlloc(self.io, try self.workspaceFile(name), self.arena, .limited(16 * 1024)) catch |err| switch (err) {
        error.FileNotFound => return error.WorkspaceNotFound,
        else => return err,
    };
    const parsed = try std.json.parseFromSlice(Workspace, self.arena, bytes, .{ .allocate = .alloc_always });
    const workspace = parsed.value;
    if (workspace.version != 1) return error.UnsupportedWorkspaceVersion;
    if (!Cli.validName(workspace.identity)) return error.InvalidIdentity;
    if (!std.fs.path.isAbsolute(workspace.path)) return error.InvalidWorkspacePath;
    return workspace;
}

/// Removes the registration, never the project or identity home.
pub fn removeWorkspace(self: Store, name: []const u8) !void {
    try self.checkRoot();
    try Dir.cwd().deleteFile(self.io, try self.workspaceFile(name));
}

pub const Kind = enum { identities, workspaces };

fn openCollection(self: Store, kind: Kind) !?Dir {
    self.checkRoot() catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    const folder = try self.path(&.{@tagName(kind)});
    return Dir.openDirAbsolute(self.io, folder, .{ .iterate = true, .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
}

pub fn names(self: Store, kind: Kind) ![]const []const u8 {
    const dir = (try self.openCollection(kind)) orelse return &.{};
    defer dir.close(self.io);
    var list: std.ArrayList([]const u8) = .empty;
    var iter = dir.iterate();
    while (try iter.next(self.io)) |entry| {
        const name = entryName(kind, entry) orelse continue;
        try list.append(self.arena, try self.arena.dupe(u8, name));
    }
    std.mem.sort([]const u8, list.items, {}, lessThan);
    return list.items;
}

fn entryName(kind: Kind, entry: Dir.Entry) ?[]const u8 {
    const name = switch (kind) {
        .identities => if (entry.kind == .directory) entry.name else return null,
        .workspaces => if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".json")) entry.name[0 .. entry.name.len - 5] else return null,
    };
    return if (Cli.validName(name)) name else null;
}

fn lessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

pub fn contains(parent: []const u8, child: []const u8) bool {
    if (std.mem.eql(u8, parent, "/")) return true;
    if (std.mem.eql(u8, parent, child)) return true;
    return std.mem.startsWith(u8, child, parent) and child.len > parent.len and child[parent.len] == '/';
}

pub fn checkWorkspacePath(project: []const u8, home: []const u8, data: []const u8) !void {
    // Never accidentally expose the whole home, another identity, or host tree.
    const parent = std.fs.path.dirname(project) orelse return error.UnsafeWorkspacePath;
    if (std.mem.eql(u8, parent, "/")) return error.UnsafeWorkspacePath;
    if (contains(project, home)) return error.UnsafeWorkspacePath;
    if (contains(project, data) or contains(data, project)) return error.UnsafeWorkspacePath;
    const forbidden = [_][]const u8{ "/etc", "/usr", "/var", "/run", "/proc", "/sys", "/dev", "/root" };
    for (forbidden) |prefix| {
        if (contains(prefix, project)) return error.UnsafeWorkspacePath;
    }
}

test "data root respects XDG and rejects relative paths" {
    const a = std.testing.allocator;
    const root = try dataRoot(a, "/home/me", null);
    defer a.free(root);
    try std.testing.expectEqualStrings("/home/me/.local/share/fella", root);
    const empty = try dataRoot(a, "/home/me", "");
    defer a.free(empty);
    try std.testing.expectEqualStrings(root, empty);
    try std.testing.expectError(error.InvalidDataHome, dataRoot(a, "/home/me", "relative"));
    try std.testing.expectError(error.InvalidHome, dataRoot(a, "relative", null));
}

test "workspace grants cannot expose homes or fella's other identities" {
    const data = "/home/me/.local/share/fella";
    const bad = [_][]const u8{ "/", "/tmp", "/opt", "/home", "/home/me", data, "/home/me/.local/share", "/home/me/.local/share/fella/identities/work", "/etc", "/etc/ssh", "/proc" };
    for (bad) |project| try std.testing.expectError(error.UnsafeWorkspacePath, checkWorkspacePath(project, "/home/me", data));
    try checkWorkspacePath("/home/me/code/project", "/home/me", data);
    try checkWorkspacePath("/home/me/.local/share/fella-project", "/home/me", data);
}
