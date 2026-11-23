// SPDX-License-Identifier: (GPL-2.0-only OR Apache-2.0)
//
// Sandwatch kernel sensor.
//
// One generic handler pair on syscall tracepoints. sys_enter captures arguments (paths, argv,
// socket addresses) for tasks in a WATCHED cgroup and parks them in `pending`; sys_exit adds
// the return value and ships the record to user space through a ring buffer.
// Syscall tracepoint argument layout is a stable ABI (args at offset 16, 8 bytes each), so no
// per-syscall structs are needed. Parent PID and process start time come from task_struct via
// CO-RE, relocated against the running kernel's BTF at load time.

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define PATH_LEN 256
#define ARG_LEN 64
#define MAX_ARGS 6
#define RET_UNFINISHED (-100000) /* call never returned: process died first */

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* Minimal CO-RE view of task_struct: only the fields we read. */
struct task_struct {
    int tgid;
    int exit_code;
    unsigned long long start_time;
    struct task_struct *real_parent;
    struct task_struct *group_leader;
} __attribute__((preserve_access_index));

struct enter_ctx {
    __u64 _hdr;
    int nr;
    int _pad;
    __u64 args[6];
};

struct exit_ctx {
    __u64 _hdr;
    int nr;
    int _pad;
    long ret;
};

/* Must match `RawEvent` in src/bpf.rs. */
struct sw_event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u64 start_ns;
    __s64 ret;
    __u64 a[4];
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 sc;    /* Sandwatch syscall code (see SC_* in src/normalize.rs) */
    __u32 argc;
    char comm[16];
    char path[PATH_LEN];
    char path2[PATH_LEN]; /* second path, or raw sockaddr bytes for connect */
    char argv[MAX_ARGS][ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} watched SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct sw_event);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sw_event);
} scratch SEC(".maps");

/* 0: ring buffer full (event lost)   1: pending map full (event lost) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &idx);
    if (v)
        __sync_fetch_and_add(v, 1);
}

static __always_inline int is_watched(void)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (bpf_map_lookup_elem(&watched, &cg))
        return 1;
#pragma unroll
    for (int i = 1; i < 10; i++) {
        __u64 a = bpf_get_current_ancestor_cgroup_id(i);
        if (!a)
            break;
        if (bpf_map_lookup_elem(&watched, &a))
            return 1;
    }
    return 0;
}

static __always_inline void fill_common(struct sw_event *e, __u32 sc)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = (__u32)id;
    e->tgid = id >> 32;
    e->uid = (__u32)bpf_get_current_uid_gid();
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->start_ns = BPF_CORE_READ(t, group_leader, start_time);
    e->sc = sc;
    e->ret = 0;
    e->argc = 0;
    e->path[0] = 0;
    e->path2[0] = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

#define IDX(i) ((i) < 0 ? 0 : (i))

/* Flag OR-ed into `sc`: arguments were recovered at syscall EXIT from saved registers
 * because the entry tracepoint never fired (the call was rejected before entry, typically
 * by seccomp, so it never really started). */
#define SC_DENIED_BEFORE_ENTRY 0x8000

#define SC_CLONE3 61

/* Fill path/sockaddr/argv fields from a syscall argument vector. `args` is either the
 * tracepoint context (entry) or a stack copy of the saved user registers (exit). */
static __always_inline void capture(struct sw_event *e, __u32 sc, const __u64 *args, int nargs,
                                    int p1, int p2, int sock, int argv_idx)
{
    e->a[0] = nargs > 0 ? args[0] : 0;
    e->a[1] = nargs > 1 ? args[1] : 0;
    e->a[2] = nargs > 2 ? args[2] : 0;
    e->a[3] = nargs > 3 ? args[3] : 0;
    /* clone3(struct clone_args *uargs, size_t size): namespace flags live in user memory,
     * in the first field (__u64 flags). Copy them into a[2] (clone3 has only two args). */
    if (sc == SC_CLONE3) {
        __u64 flags = 0;
        bpf_probe_read_user(&flags, sizeof(flags), (const void *)args[0]);
        e->a[2] = flags;
    }
    if (p1 >= 0)
        bpf_probe_read_user_str(e->path, PATH_LEN, (const void *)args[IDX(p1)]);
    if (p2 >= 0)
        bpf_probe_read_user_str(e->path2, PATH_LEN, (const void *)args[IDX(p2)]);
    if (sock >= 0) {
        const void *sa = (const void *)args[IDX(sock)];
        __u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), sa);
        if (family == 1 /* AF_UNIX */)
            bpf_probe_read_user(e->path2, 110, sa);
        else
            bpf_probe_read_user(e->path2, 28, sa); /* fits sockaddr_in and sockaddr_in6 */
    }
    if (argv_idx >= 0) {
        const char *const *argv = (const char *const *)args[IDX(argv_idx)];
#pragma unroll
        for (int i = 0; i < MAX_ARGS; i++) {
            const char *p = 0;
            if (bpf_probe_read_user(&p, sizeof(p), &argv[i]) || !p)
                break;
            bpf_probe_read_user_str(e->argv[i], ARG_LEN, p);
            e->argc = i + 1;
        }
    }
}

/* nargs: how many arguments this syscall's tracepoint has. The kernel refuses to attach a
 * program that reads past the end of the tracepoint context, so we only touch args that
 * exist (nargs is a compile-time constant per call site; the dead reads are removed). */
static __always_inline int do_enter(struct enter_ctx *ctx, __u32 sc, int nargs, int p1, int p2,
                                    int sock, int argv_idx)
{
    if (!is_watched())
        return 0;
    __u32 zero = 0;
    struct sw_event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, sc);
    capture(e, sc, ctx->args, nargs, p1, p2, sock, argv_idx);
    __u64 id = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&pending, &id, e, BPF_ANY))
        bump(1);
    return 0;
}

#if defined(__TARGET_ARCH_x86)
/* CO-RE view of the saved user registers (x86-64 syscall ABI: di si dx r10 r8 r9). */
struct pt_regs {
    unsigned long di, si, dx, r10, r8, r9;
} __attribute__((preserve_access_index));

static __always_inline int saved_args(__u64 *a)
{
    struct pt_regs *r = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
    if (!r)
        return 0;
    a[0] = BPF_CORE_READ(r, di);
    a[1] = BPF_CORE_READ(r, si);
    a[2] = BPF_CORE_READ(r, dx);
    a[3] = BPF_CORE_READ(r, r10);
    a[4] = BPF_CORE_READ(r, r8);
    a[5] = BPF_CORE_READ(r, r9);
    return 1;
}
#else
static __always_inline int saved_args(__u64 *a) { return 0; }
#endif

static __always_inline int do_exit(struct exit_ctx *ctx, __u32 sc, int nargs, int p1, int p2,
                                   int sock, int argv_idx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct sw_event *e = bpf_map_lookup_elem(&pending, &id);
    if (e) {
        e->ret = ctx->ret;
        if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
            bump(0);
        bpf_map_delete_elem(&pending, &id);
        return 0;
    }
    /* Exit without entry + error: rejected before the entry tracepoint (seccomp). These are
     * exactly the calls a sandbox blocks, so record them. (A clone child returning 0 also has
     * no entry, but does not fail, so it is not caught here.) */
    if (ctx->ret >= 0 || !is_watched())
        return 0;
    __u32 zero = 0;
    struct sw_event *s = bpf_map_lookup_elem(&scratch, &zero);
    if (!s)
        return 0;
    fill_common(s, sc | SC_DENIED_BEFORE_ENTRY);
    __u64 args[6] = {};
    if (saved_args(args))
        capture(s, sc, args, nargs, p1, p2, sock, argv_idx);
    s->ret = ctx->ret;
    if (bpf_ringbuf_output(&events, s, sizeof(*s), 0))
        bump(0);
    return 0;
}

#define SC_TERMINATE 90

/* Process exit (any cause, including signals). Flushes a call that never returned and
 * reports the thread-group leader's termination. */
SEC("tracepoint/sched/sched_process_exit")
int sched_exit(void *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct sw_event *p = bpf_map_lookup_elem(&pending, &id);
    if (p) {
        p->ret = RET_UNFINISHED;
        if (bpf_ringbuf_output(&events, p, sizeof(*p), 0))
            bump(0);
        bpf_map_delete_elem(&pending, &id);
    }
    if ((__u32)id != (id >> 32) || !is_watched())
        return 0;
    __u32 zero = 0;
    struct sw_event *e = bpf_map_lookup_elem(&scratch, &zero);
    if (!e)
        return 0;
    fill_common(e, SC_TERMINATE);
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ret = BPF_CORE_READ(t, exit_code);
    if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
        bump(0);
    return 0;
}

/* name, Sandwatch code, arg count, path arg, path2 arg, sockaddr arg, argv arg  (-1 = none) */
#define TP(name, sc, nargs, p1, p2, sock, argv)                                              \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                              \
    int enter_##name(struct enter_ctx *ctx)                                                  \
    { return do_enter(ctx, sc, nargs, p1, p2, sock, argv); }                                 \
    SEC("tracepoint/syscalls/sys_exit_" #name)                                               \
    int exit_##name(struct exit_ctx *ctx)                                                    \
    { return do_exit(ctx, sc, nargs, p1, p2, sock, argv); }

/* Codes must match the SPECS table in src/normalize.rs. */
TP(open, 1, 3,  0, -1, -1, -1)
TP(openat, 2, 4,  1, -1, -1, -1)
TP(openat2, 3, 4,  1, -1, -1, -1)
TP(creat, 4, 2,  0, -1, -1, -1)
TP(newfstatat, 5, 4,  1, -1, -1, -1)
TP(statx, 6, 5,  1, -1, -1, -1)
TP(newstat, 7, 2,  0, -1, -1, -1)
TP(newlstat, 8, 2,  0, -1, -1, -1)
TP(access, 9, 2,  0, -1, -1, -1)
TP(faccessat, 10, 3, 1, -1, -1, -1)
TP(faccessat2, 11, 4, 1, -1, -1, -1)
TP(readlink, 12, 3, 0, -1, -1, -1)
TP(readlinkat, 13, 4, 1, -1, -1, -1)
TP(unlink, 14, 1, 0, -1, -1, -1)
TP(unlinkat, 15, 3, 1, -1, -1, -1)
TP(rmdir, 16, 1, 0, -1, -1, -1)
TP(rename, 17, 2, 0,  1, -1, -1)
TP(renameat, 18, 4, 1,  3, -1, -1)
TP(renameat2, 19, 5, 1,  3, -1, -1)
TP(mkdir, 20, 2, 0, -1, -1, -1)
TP(mkdirat, 21, 3, 1, -1, -1, -1)
TP(chdir, 22, 1, 0, -1, -1, -1)
TP(chmod, 23, 2, 0, -1, -1, -1)
TP(fchmodat, 24, 3, 1, -1, -1, -1)
TP(chown, 25, 3, 0, -1, -1, -1)
TP(fchownat, 26, 5, 1, -1, -1, -1)
TP(symlink, 27, 2, 1,  0, -1, -1)
TP(symlinkat, 28, 3, 2,  0, -1, -1)
TP(execve, 30, 3, 0, -1, -1,  1)
TP(execveat, 31, 5, 1, -1, -1,  2)
TP(connect, 40, 3, -1, -1, 1, -1)
TP(unshare, 50, 1, -1, -1, -1, -1)
TP(setns, 51, 2, -1, -1, -1, -1)
TP(mount, 52, 5, 1,  0, -1, -1)
TP(umount, 53, 2, 0, -1, -1, -1)
TP(ptrace, 54, 4, -1, -1, -1, -1)
TP(bpf, 55, 3, -1, -1, -1, -1)
TP(clone, 60, 5, -1, -1, -1, -1)
TP(clone3, 61, 2, -1, -1, -1, -1)
TP(fork, 62, 0, -1, -1, -1, -1)
TP(vfork, 63, 0, -1, -1, -1, -1)
TP(kill, 64, 2, -1, -1, -1, -1)
TP(tkill, 65, 2, -1, -1, -1, -1)
TP(tgkill, 66, 3, -1, -1, -1, -1)
TP(setuid, 70, 1, -1, -1, -1, -1)
TP(setgid, 71, 1, -1, -1, -1, -1)
TP(setresuid, 72, 3, -1, -1, -1, -1)
TP(setresgid, 73, 3, -1, -1, -1, -1)
TP(setreuid, 74, 2, -1, -1, -1, -1)
TP(setregid, 75, 2, -1, -1, -1, -1)
