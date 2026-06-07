const std = @import("std");

/// SecureBuffer wraps sensitive data with anti-forensic protections:
/// - mlock() to prevent swapping to disk
/// - madvise(MADV_DONTDUMP) to exclude from core dumps
/// - secureZero() on deinit to prevent memory residual
pub fn SecureBuffer(comptime T: type) type {
    return struct {
        data: []T,
        allocator: std.mem.Allocator,

        const Self = @This();
        const MADV_DONTDUMP: u32 = 16;

        pub fn alloc(allocator: std.mem.Allocator, n: usize) !Self {
            const data = try allocator.alloc(T, n);
            errdefer allocator.free(data);

            // Lock pages into RAM (prevent swap)
            const data_bytes = std.mem.sliceAsBytes(data);
            _ = std.os.linux.mlock(data_bytes.ptr, data_bytes.len);

            // Exclude from core dumps
            _ = std.os.linux.madvise(data_bytes.ptr, data_bytes.len, MADV_DONTDUMP);

            return .{ .data = data, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            // Zero before free
            const data_bytes = std.mem.sliceAsBytes(self.data);
            std.crypto.secureZero(u8, data_bytes);

            // Unlock pages
            _ = std.os.linux.munlock(data_bytes.ptr, data_bytes.len);

            self.allocator.free(self.data);
        }

        pub fn slice(self: *const Self) []T {
            return self.data;
        }
    };
}
