// MAGI Linux telemetry — raw eBPF probes loaded by ebpf_collector.py via bcc.
//
// Traces two syscall tracepoints:
//   syscalls:sys_enter_execve  -> process execution chains  (event_type "process")
//   syscalls:sys_enter_connect -> outbound TCP/UDP connects (event_type "network")
//
// Events are pushed to userspace over BPF_PERF_OUTPUT ring buffers. bcc rewrites
// pointer dereferences (e.g. task->real_parent->tgid) into bpf_probe_read calls
// at compile time, so the kernel verifier stays happy.

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME 200

struct connect_event_t {
    u64 ts_ns;
    u32 pid;
    u32 uid;
    u16 family;       // AF_INET (2) or AF_INET6 (10)
    u16 dport;        // network byte order; ntohs in userspace
    u32 daddr_v4;     // network byte order; inet_ntoa in userspace
    u8  daddr_v6[16];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(connect_events);

struct exec_event_t {
    u64 ts_ns;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME];
};
BPF_PERF_OUTPUT(exec_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr *addr = (struct sockaddr *)args->uservaddr;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

    // Only IPv4/IPv6 sockets matter for threat correlation; skip AF_UNIX et al.
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct connect_event_t evt = {};
    evt.ts_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;
    evt.family = family;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    if (family == AF_INET) {
        struct sockaddr_in *in4 = (struct sockaddr_in *)addr;
        bpf_probe_read_user(&evt.daddr_v4, sizeof(evt.daddr_v4), &in4->sin_addr.s_addr);
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &in4->sin_port);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        bpf_probe_read_user(&evt.daddr_v6, sizeof(evt.daddr_v6), &in6->sin6_addr);
        bpf_probe_read_user(&evt.dport, sizeof(evt.dport), &in6->sin6_port);
    }

    connect_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t evt = {};
    evt.ts_ns = bpf_ktime_get_ns();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.uid = bpf_get_current_uid_gid() & 0xffffffff;

    // bcc rewrites these dereferences into safe bpf_probe_read_kernel calls.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    evt.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->filename);

    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
