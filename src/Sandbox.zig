const std = @import("std");
const Output = @import("Output.zig");

// Seccomp-bpf sandbox for the fella process.
// Deny-list approach: blocks a small set of high-leverage attack syscalls
// while allowing normal operation. This is a nation-state tier containment
// layer — even a memory corruption bug in fella cannot call ptrace,
// load a kernel module, or mmap a userfaultfd.

const PR_SET_NO_NEW_PRIVS = 38;
const PR_SET_SECCOMP = 22;
const SECCOMP_MODE_FILTER = 2;
const SECCOMP_RET_KILL_PROCESS = 0x80000000;
const SECCOMP_RET_ALLOW = 0x7fff0000;
const AUDIT_ARCH_AARCH64 = 0xC00000B7;

const BPF_LD_W_ABS = 0x20;
const BPF_JMP_JEQ_K = 0x15;
const BPF_RET_K = 0x06;

const sock_filter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const sock_fprog = extern struct {
    len: u16,
    filter: [*]const sock_filter,
};

// Syscalls blocked on aarch64. These are the highest-leverage primitives
// for sandbox escape, privilege escalation, and side-channel exfiltration.
const DENIED = [_]u32{
    117, // ptrace
    270, // process_vm_readv
    271, // process_vm_writev
    265, // open_by_handle_at
    241, // perf_event_open
    282, // userfaultfd
    104, // kexec_load
    294, // kexec_file_load
    105, // init_module
    273, // finit_module
    106, // delete_module
    217, // add_key
    218, // request_key
    219, // keyctl
    280, // bpf
};

const FILTER_LEN = 4 + (DENIED.len * 2) + 1;

fn makeFilter() [FILTER_LEN]sock_filter {
    var f: [FILTER_LEN]sock_filter = undefined;
    var i: usize = 0;

    // if (arch != AARCH64) kill
    f[i] = .{ .code = BPF_LD_W_ABS, .jt = 0, .jf = 0, .k = 4 };
    i += 1;
    f[i] = .{ .code = BPF_JMP_JEQ_K, .jt = 1, .jf = 0, .k = AUDIT_ARCH_AARCH64 };
    i += 1;
    f[i] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
    i += 1;

    // load syscall number
    f[i] = .{ .code = BPF_LD_W_ABS, .jt = 0, .jf = 0, .k = 0 };
    i += 1;

    // for each denied syscall: if (nr == X) kill
    for (DENIED) |nr| {
        f[i] = .{ .code = BPF_JMP_JEQ_K, .jt = 0, .jf = 1, .k = nr };
        i += 1;
        f[i] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_KILL_PROCESS };
        i += 1;
    }

    // allow everything else
    f[i] = .{ .code = BPF_RET_K, .jt = 0, .jf = 0, .k = SECCOMP_RET_ALLOW };
    i += 1;

    std.debug.assert(i == FILTER_LEN);
    return f;
}

pub fn apply(io: std.Io, alloc: std.mem.Allocator) !void {
    // Prevent privilege escalation via setuid binaries in any child we exec.
    const rc_nnp = std.os.linux.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (rc_nnp != 0) {
        try Output.stdoutPrint(io, alloc, "    [!] prctl(NO_NEW_PRIVS) failed: {s}\n", .{@tagName(std.posix.errno(rc_nnp))});
    }

    var filter = makeFilter();
    const prog = sock_fprog{
        .len = FILTER_LEN,
        .filter = &filter,
    };

    const rc = std.os.linux.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, @intFromPtr(&prog), 0, 0);
    if (rc != 0) {
        const e = std.posix.errno(rc);
        try Output.stdoutPrint(io, alloc, "    [!] seccomp filter load failed: {s}\n", .{@tagName(e)});
        return error.SeccompLoadFailed;
    }

    try Output.stdoutPrint(io, alloc, "    [*] Seccomp-bpf sandbox active ({d} syscalls blocked)\n", .{DENIED.len});
}

const PR_GET_SECCOMP = 21;

pub fn isActive() bool {
    const rc = std.os.linux.prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    return rc == 2;
}

pub fn describe(io: std.Io, alloc: std.mem.Allocator) !void {
    const state = if (isActive()) "filter mode active" else "inactive";
    try Output.stdoutPrint(io, alloc, "Seccomp:    {s} ({d} syscalls blocked if active)\n", .{ state, DENIED.len });
}
