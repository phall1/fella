const std = @import("std");
const Output = @import("Output.zig");

const PR_SET_NAME = 15;

// Boring process names that won't raise eyebrows in `ps` output.
// Nation-state adversaries often target processes by name; looking like
// a common systemd service is a cheap but effective obfuscation layer.
const FAKE_NAMES = [_][]const u8{
    "systemd-resolve",  // 15 + null
    "systemd-network",  // 15 + null
    "systemd-timeync",  // 15 + null
    "dbus-daemon",
    "rsyslogd",
    "cron",
    "networkd-dispat",  // 15 + null
    "irqbalance",
};

pub fn apply(io: std.Io, alloc: std.mem.Allocator) !void {
    var seed_buf: [8]u8 = undefined;
    _ = std.os.linux.getrandom(&seed_buf, seed_buf.len, 0);
    const seed = std.mem.readInt(u64, &seed_buf, .little);
    var prng = std.Random.DefaultPrng.init(seed);
    const idx = prng.random().int(u32) % FAKE_NAMES.len;
    const name = FAKE_NAMES[idx];

    // prctl(PR_SET_NAME, name, 0, 0, 0)
    const rc = std.os.linux.prctl(PR_SET_NAME, @intFromPtr(name.ptr), 0, 0, 0);
    if (rc != 0) {
        try Output.stdoutPrint(io, alloc, "    [!] Could not masquerade process name\n", .{});
        return error.MasqueradeFailed;
    }

    try Output.stdoutPrint(io, alloc, "    [*] Process masqueraded as '{s}'\n", .{name});
}
