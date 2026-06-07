const std = @import("std");
const Output = @import("Output.zig");

const MOUNT_POINT: [:0]const u8 = "/var/lib/fella";
const STATE_PATH: [:0]const u8 = "/var/lib/fella/state";

/// Mount /var/lib/fella as a tmpfs so all session state lives in RAM.
/// This makes the entire session fileless: state, tor data, identity backups,
/// and configs all evaporate on power loss or unmount.
pub fn mount(io: std.Io, alloc: std.mem.Allocator) !void {
    // Ensure mount point exists
    _ = std.os.linux.mkdir(MOUNT_POINT, 0o700);

    const fs_type: [:0]const u8 = "tmpfs";
    var options: [64:0]u8 = undefined;
    const opt_str = std.fmt.bufPrint(&options, "size=50M,mode=700,uid=0,gid=0", .{}) catch "size=50M,mode=700";
    options[opt_str.len] = 0;

    const rc = std.os.linux.mount(
        fs_type,
        MOUNT_POINT,
        fs_type,
        0,
        @intFromPtr(&options),
    );
    if (rc != 0) {
        const e = std.posix.errno(rc);
        try Output.stdoutPrint(io, alloc, "    [!] tmpfs mount failed: {s}\n", .{@tagName(e)});
        return error.MountFailed;
    }

    try Output.stdoutPrint(io, alloc, "    [*] Ephemeral tmpfs mounted at {s}\n", .{MOUNT_POINT});
}

pub fn unmount(io: std.Io, alloc: std.mem.Allocator) !void {
    const rc = std.os.linux.umount2(MOUNT_POINT, 0x00000002); // MNT_DETACH
    if (rc != 0) {
        const e = std.posix.errno(rc);
        try Output.stdoutPrint(io, alloc, "    [!] tmpfs unmount failed: {s}\n", .{@tagName(e)});
    } else {
        try Output.stdoutPrint(io, alloc, "    [+] Ephemeral tmpfs unmounted\n", .{});
    }
}

pub fn isMounted() bool {
    // Heuristic: if /var/lib/fella/state doesn't exist but the dir is readable,
    // assume we just mounted an empty tmpfs.
    const state_fd = std.posix.openatZ(-100, STATE_PATH, .{ .ACCMODE = .RDONLY }, 0) catch {
        // State file missing — could be fresh tmpfs or never initialized.
        // Check if the directory itself is accessible.
        const dir_fd = std.posix.openatZ(-100, MOUNT_POINT, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch return false;
        _ = std.os.linux.close(dir_fd);
        return true;
    };
    _ = std.os.linux.close(state_fd);
    return false;
}
