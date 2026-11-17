const std = @import("std");

pub const Add = struct { name: []const u8, identity: []const u8, path: []const u8 };
pub const Enter = struct { name: []const u8, offline: bool = false, argv: []const []const u8 = &.{} };
pub const Command = union(enum) {
    help,
    version,
    doctor,
    identity_create: []const u8,
    identity_list,
    identity_path: []const u8,
    workspace_add: Add,
    workspace_list,
    workspace_remove: []const u8,
    show: []const u8,
    enter: Enter,
};

pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > 48) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    }
    return true;
}

fn named(args: []const []const u8) ![]const u8 {
    if (args.len != 1) return error.InvalidArguments;
    if (!validName(args[0])) return error.InvalidName;
    return args[0];
}

pub fn parse(args: []const []const u8) !Command {
    if (args.len == 0) return .help;
    const cmd = args[0];
    if (std.mem.eql(u8, cmd, "identity")) return parseIdentity(args[1..]);
    if (std.mem.eql(u8, cmd, "workspace")) return parseWorkspace(args[1..]);
    if (std.mem.eql(u8, cmd, "enter")) return .{ .enter = try parseEnter(args[1..]) };
    if (std.mem.eql(u8, cmd, "show")) return .{ .show = try named(args[1..]) };
    return parseSimple(args);
}

fn parseSimple(args: []const []const u8) !Command {
    if (args.len != 1) return error.InvalidArguments;
    const table = .{
        .{ "help", Command.help },       .{ "--help", Command.help },       .{ "-h", Command.help },
        .{ "version", Command.version }, .{ "--version", Command.version }, .{ "doctor", Command.doctor },
    };
    inline for (table) |entry| {
        if (std.mem.eql(u8, args[0], entry[0])) return entry[1];
    }
    return error.UnknownCommand;
}

fn parseIdentity(args: []const []const u8) !Command {
    if (args.len == 0) return error.InvalidArguments;
    if (std.mem.eql(u8, args[0], "create")) return .{ .identity_create = try named(args[1..]) };
    if (std.mem.eql(u8, args[0], "path")) return .{ .identity_path = try named(args[1..]) };
    if (args.len == 1 and std.mem.eql(u8, args[0], "list")) return .identity_list;
    return error.InvalidArguments;
}

fn parseWorkspace(args: []const []const u8) !Command {
    if (args.len == 0) return error.InvalidArguments;
    if (std.mem.eql(u8, args[0], "add")) return .{ .workspace_add = try parseAdd(args[1..]) };
    if (std.mem.eql(u8, args[0], "remove")) return .{ .workspace_remove = try named(args[1..]) };
    if (args.len == 1 and std.mem.eql(u8, args[0], "list")) return .workspace_list;
    return error.InvalidArguments;
}

fn parseAdd(args: []const []const u8) !Add {
    if (args.len != 5) return error.InvalidArguments;
    const name = try named(args[0..1]);
    if (std.mem.eql(u8, args[1], "--path")) {
        return addPairs(name, args[3..5], args[1..3]);
    }
    return addPairs(name, args[1..3], args[3..5]);
}

fn addPairs(name: []const u8, identity: []const []const u8, path: []const []const u8) !Add {
    if (!std.mem.eql(u8, identity[0], "--identity")) return error.InvalidArguments;
    if (!std.mem.eql(u8, path[0], "--path")) return error.InvalidArguments;
    return .{ .name = name, .identity = try named(identity[1..2]), .path = path[1] };
}

fn parseEnter(args: []const []const u8) !Enter {
    if (args.len == 0) return error.InvalidArguments;
    var result: Enter = .{ .name = try named(args[0..1]) };
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--")) {
            if (i + 1 == args.len) return error.InvalidArguments;
            result.argv = args[i + 1 ..];
            return result;
        }
        if (!std.mem.eql(u8, args[i], "--offline") or result.offline) return error.InvalidArguments;
        result.offline = true;
    }
    return result;
}

test "names cannot escape storage paths" {
    for ([_][]const u8{ "", ".", "..", "../work", "a/b", "a b", "--flag\n" }) |name| {
        try std.testing.expect(!validName(name));
    }
    try std.testing.expect(validName("work-2_private"));
    const too_long: [49]u8 = @splat('a');
    try std.testing.expect(!validName(&too_long));
}

test "enter preserves arguments verbatim after delimiter" {
    const cmd = try parse(&.{ "enter", "work", "--offline", "--", "printf", "%s", "a'b $HOME", "--offline" });
    try std.testing.expect(cmd.enter.offline);
    try std.testing.expectEqualStrings("a'b $HOME", cmd.enter.argv[2]);
    try std.testing.expectEqualStrings("--offline", cmd.enter.argv[3]);
}

test "invalid options and incomplete commands fail closed" {
    const bad = [_][]const []const u8{
        &.{ "enter", "work", "--unsafe" },
        &.{ "enter", "work", "--offline", "--offline" },
        &.{ "enter", "work", "--" },
        &.{ "workspace", "add", "p", "--path", "/p", "--path", "/q" },
        &.{ "workspace", "add", "p", "--identity", "work" },
        &.{ "identity", "create", "../work" },
        &.{ "doctor", "extra" },
    };
    for (bad) |args| {
        const result = parse(args);
        try std.testing.expect(std.meta.isError(result));
    }
}

test "workspace registration accepts either option order" {
    const cmd = try parse(&.{ "workspace", "add", "project", "--path", "./a b", "--identity", "work" });
    try std.testing.expectEqualStrings("./a b", cmd.workspace_add.path);
    try std.testing.expectEqualStrings("work", cmd.workspace_add.identity);
}
