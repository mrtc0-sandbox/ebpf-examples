#!/usr/bin/python3
from bcc import BPF

bpf_text="""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char fname[128];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    bpf_probe_read_user(data.fname, sizeof(data.fname), (void *)filename);

    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
"""

b = BPF(text=bpf_text)
b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="syscall__execve")

print("PID      PPID     COMM             FNAME")
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("{:<8} {:<8} {:16} {}".format(event.pid, event.ppid, event.comm.decode(), event.fname.decode()))

b["events"].open_perf_buffer(print_event)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
