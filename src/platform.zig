const std = @import("std");

pub const Environment = struct {
    alloc: std.mem.Allocator,
    virt: []const u8,
    container_runtime: ?[]const u8,
    init_system: []const u8,
    primary_iface: []const u8,
    has_sys_admin: bool,
    has_net_admin: bool,
    can_compile_c: bool,

    pub fn deinit(self: *const Environment) void {
        self.alloc.free(self.virt);
        if (self.container_runtime) |cr| self.alloc.free(cr);
        self.alloc.free(self.init_system);
        self.alloc.free(self.primary_iface);
    }
};

pub fn probe(alloc: std.mem.Allocator) !Environment {
    const linux = @import("platform/linux.zig");
    return linux.probe(alloc);
}
