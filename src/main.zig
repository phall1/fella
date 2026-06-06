const std = @import("std");
const clap = @import("clap");
const Engine = @import("Engine.zig");
const platform = @import("platform.zig");
const Output = @import("Output.zig");

const BANNER =
    \\   _____     __
    \\  / __(_)__ / /  ___ ___
    \\ / _// (_-< / _ \/ -_) _ \
    \\\/_/ /_/___/_//_/\__/_//_/
    \\
;

const params = clap.parseParamsComptime(
    \\-h, --help    Display this help and exit.
    \\-v, --version Display version and exit.
    \\<str>
    \\
);

fn printBanner(io: std.Io, alloc: std.mem.Allocator) !void {
    try Output.stdoutPrint(io, alloc, "{s}{s}{s}\n", .{ Output.Color.blue, BANNER, Output.Color.reset });
}

fn printHelp(io: std.Io) !void {
    try Output.stdoutWrite(io,
        \\
        \\Usage: fella <command>
        \\
        \\Commands:
        \\  init        First-time setup, probe environment
        \\  start       Activate identity + tor + basic killswitch
        \\  lockdown    Full strict mode (tor-only traffic)
        \\  stop        Deactivate everything, restore system
        \\  rotate      New identity + new tor circuit
        \\  status      Full posture report
        \\  verify      Run leak and health tests
        \\  shell       Drop into tor-routed subshell
        \\  wipe        Clear session artifacts
        \\  harden      Apply environment patches
        \\  doctor      Diagnose environment and installation
        \\  help        Show this message
        \\  version     Show version
        \\
    );
}

pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;
    const io = init.io;

    var iter = try init.minimal.args.iterateAllocator(alloc);
    defer iter.deinit();

    // Skip argv[0]
    _ = iter.next();

    var diag = clap.Diagnostic{};
    var res = clap.parseEx(clap.Help, &params, clap.parsers.default, &iter, .{
        .diagnostic = &diag,
        .allocator = alloc,
        .terminating_positional = 0,
    }) catch |err| {
        try diag.reportToFile(io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try printHelp(io);
        return;
    }

    if (res.args.version != 0) {
        try Output.stdoutPrint(io, alloc, "fella 0.1.0\n", .{});
        return;
    }

    const cmd = res.positionals[0] orelse {
        try printHelp(io);
        std.process.exit(1);
    };

    const env = if (needsEnv(cmd))
        try platform.probe(alloc)
    else
        null;
    defer if (env) |e| e.deinit();

    var engine = if (env) |e| try Engine.create(alloc, e) else null;
    defer if (engine) |*eng| eng.deinit();

    if (std.mem.eql(u8, cmd, "init")) {
        try printBanner(io, alloc);
        try engine.?.init(io, alloc);
    } else if (std.mem.eql(u8, cmd, "start")) {
        try printBanner(io, alloc);
        try engine.?.start(io, alloc);
    } else if (std.mem.eql(u8, cmd, "lockdown")) {
        try printBanner(io, alloc);
        try engine.?.lockdown(io, alloc);
    } else if (std.mem.eql(u8, cmd, "stop")) {
        try engine.?.stop(io, alloc);
    } else if (std.mem.eql(u8, cmd, "rotate")) {
        try engine.?.rotate(io, alloc);
    } else if (std.mem.eql(u8, cmd, "status")) {
        try engine.?.status(io, alloc);
    } else if (std.mem.eql(u8, cmd, "verify")) {
        try engine.?.verify(io, alloc);
    } else if (std.mem.eql(u8, cmd, "shell")) {
        try engine.?.shell(io, alloc);
    } else if (std.mem.eql(u8, cmd, "wipe")) {
        try engine.?.wipe(io, alloc);
    } else if (std.mem.eql(u8, cmd, "harden")) {
        try engine.?.harden(io, alloc);
    } else if (std.mem.eql(u8, cmd, "doctor")) {
        try printBanner(io, alloc);
        try engine.?.doctor(io, alloc);
    } else if (std.mem.eql(u8, cmd, "help")) {
        try printHelp(io);
    } else if (std.mem.eql(u8, cmd, "version")) {
        try Output.stdoutPrint(io, alloc, "fella 0.1.0\n", .{});
    } else {
        try Output.stderrWrite(io, "Unknown command: ");
        try Output.stderrWrite(io, cmd);
        try Output.stderrWrite(io, "\n");
        try printHelp(io);
        std.process.exit(1);
    }
}

fn needsEnv(cmd: []const u8) bool {
    const env_cmds = .{ "init", "start", "lockdown", "stop", "rotate", "status", "verify", "shell", "wipe", "harden", "doctor" };
    inline for (env_cmds) |c| {
        if (std.mem.eql(u8, cmd, c)) return true;
    }
    return false;
}
