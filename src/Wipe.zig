const std = @import("std");
const Output = @import("Output.zig");

const PASSES = 3;

pub fn dir(io: std.Io, alloc: std.mem.Allocator, path: []const u8) !void {
    try Output.stdoutPrint(io, alloc, "[+] Securely wiping {s}...\n", .{path});
    try wipePath(path);
    try Output.stdoutPrint(io, alloc, "    [+] Wipe complete\n", .{});
}

fn wipePath(path: []const u8) !void {
    var path_z: [512:0]u8 = undefined;
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    // Try directory first
    const dir_fd = std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0) catch null;
    if (dir_fd) |fd| {
        defer _ = std.os.linux.close(fd);

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = std.os.linux.getdents64(fd, &buf, buf.len);
            if (n == 0) break;
            if (n > 0x7FFFFFFFFFFFFFFF) break; // negative as signed -> error

            var pos: usize = 0;
            while (pos < n) {
                const entry = @as(*align(1) linux_dirent64, @ptrCast(&buf[pos]));
                const name_ptr: [*:0]const u8 = @ptrCast(&entry.name);
                const name = std.mem.sliceTo(name_ptr, 0);
                if (!std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..")) {
                    var child_z: [512:0]u8 = undefined;
                    const child = std.fmt.bufPrint(&child_z, "{s}/{s}", .{ path, name }) catch continue;
                    try wipePath(child_z[0..child.len]);
                }
                pos += entry.reclen;
            }
        }

        const rc = std.os.linux.rmdir(&path_z);
        if (rc > 0x7FFFFFFFFFFFFFFF) return error.WipeFailed;
        return;
    }

    // File: secure overwrite then unlink
    const fd = std.posix.openatZ(-100, &path_z, .{ .ACCMODE = .WRONLY }, 0) catch {
        _ = std.os.linux.unlink(&path_z);
        return;
    };
    defer _ = std.os.linux.close(fd);

    const size = @as(usize, @intCast(std.os.linux.lseek(fd, 0, 2)));
    _ = std.os.linux.lseek(fd, 0, 0);

    if (size == 0) {
        _ = std.os.linux.unlink(&path_z);
        return;
    }

    const block = try std.heap.page_allocator.alloc(u8, @min(size, 65536));
    defer std.heap.page_allocator.free(block);

    _ = std.os.linux.getrandom(block.ptr, block.len, 0);
    _ = overwrite(fd, block, size);
    for (block) |*b| b.* = ~b.*;
    _ = overwrite(fd, block, size);
    _ = std.os.linux.getrandom(block.ptr, block.len, 0);
    _ = overwrite(fd, block, size);
    _ = std.os.linux.fsync(fd);
    _ = std.os.linux.unlink(&path_z);
}

fn overwrite(fd: i32, block: []u8, total: usize) usize {
    var written: usize = 0;
    while (written < total) {
        const chunk = @min(block.len, total - written);
        const n = std.os.linux.pwrite(fd, block.ptr, chunk, @intCast(written));
        if (n <= 0) break;
        written += n;
    }
    return written;
}

const linux_dirent64 = extern struct {
    ino: u64,
    off: i64,
    reclen: u16,
    type: u8,
    name: [1]u8,
};
