const std = @import("std");

/// Global interruption flag set by SIGINT / SIGTERM handlers.
/// Checked by long-running operations to enable graceful cleanup.
var g_interrupted = std.atomic.Value(bool).init(false);

fn handler(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    g_interrupted.store(true, .seq_cst);
}

/// Install SIGINT and SIGTERM handlers that set the interrupted flag.
pub fn install() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = handler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Restore default signal handlers.
pub fn uninstall() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Returns true if an interrupt signal has been received since the last reset.
pub fn isInterrupted() bool {
    return g_interrupted.load(.seq_cst);
}

/// Clear the interruption flag. Call after successful cleanup.
pub fn reset() void {
    g_interrupted.store(false, .seq_cst);
}
