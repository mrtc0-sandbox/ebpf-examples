#!/usr/bin/python3
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

bpf_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused = (void *) BPF_FUNC_##NAME
#endif

static int BPF_FUNC(send_signal, uint32_t sig);

BPF_HASH(currsock, u32, struct sock *);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	currsock.update(&pid, &sk);
    send_signal(9);

	return 0;
};

int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

	struct sock **skpp;
	skpp = currsock.lookup(&pid);
	if (skpp == 0) {
		return 0;
	}

	if (ret != 0) {
		currsock.delete(&pid);
		return 0;
	}

	struct sock *skp = *skpp;
	u32 saddr = skp->__sk_common.skc_rcv_saddr;
	u32 daddr = skp->__sk_common.skc_daddr;
	u16 dport = skp->__sk_common.skc_dport;

	bpf_trace_printk("trace_tcp4connect %x %x %d\\n", saddr, daddr, ntohs(dport));

	currsock.delete(&pid);

	return 0;
}
"""

b = BPF(text=bpf_text)

print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

while 1:
	try:
	    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
	    (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
	except ValueError:
	    continue
	except KeyboardInterrupt:
	    exit()

	if _tag.decode() != "trace_tcp4connect":
	    continue

	printb(b"%-6d %-12.12s %-16s %-16s %-4s" % (pid, task,
	    inet_ntoa(int(saddr_hs, 16)),
	    inet_ntoa(int(daddr_hs, 16)),
	    dport_s))
