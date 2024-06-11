# Created to try and see if it is possible to get HTTPS request/response in a K8's environment without neededing a proxy
# such as mitm proxy, Fiddler etc.
# So far only TLS info for TCP connections is working, HTTP request/response is still a work in progress.
from bcc import BPF
import argparse
import ctypes

class Data(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("ts", ctypes.c_uint64),
        ("comm", ctypes.c_char * 16),
        ("buf", ctypes.c_char * 256),
        ("buflen", ctypes.c_size_t),
    ]

# ebpf program
ebpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char buf[256];
    size_t buflen;
};

BPF_PERF_OUTPUT(read_events);
BPF_PERF_OUTPUT(write_events);

int trace_read(struct pt_regs *ctx, int fd, void *buf, size_t count) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    if (count > 0) {
        int len = count & 255; 
        bpf_probe_read_user(&data.buf, len, buf);
        data.buflen = len;
    }

    read_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_write(struct pt_regs *ctx, int fd, const void *buf, size_t count) {
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // had to add a limit of 255 for the count lenghth to avoid memory errors. can also be represented in hex 0xff
    if (count > 0) {
        int len = count & 255;
        bpf_probe_read_user(&data.buf, len, buf);
        data.buflen = len;
    }

    write_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

parser = argparse.ArgumentParser(description='Trace read/write functions (libc) for a specific process')
parser.add_argument('pid', type=int, help='PID to trace')
args = parser.parse_args()

b = BPF(text=ebpf_program)

# Attach uprobes to the read and write functions in libc, this was used instead of direct probes on openssl (SSL_read, SSL_write) fucntions to make the app work regardless of the client/server language.
b.attach_uprobe(name="c", sym="read", fn_name="trace_read", pid=args.pid)
b.attach_uprobe(name="c", sym="write", fn_name="trace_write", pid=args.pid)

'''
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_read", fn_name="trace_ssl_read", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_write", fn_name="trace_ssl_write", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_connect", fn_name="trace_ssl_connect", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_accept", fn_name="trace_ssl_accept", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_shutdown", fn_name="trace_ssl_shutdown", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_set_cipher_list", fn_name="trace_ssl_set_cipher_list", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_CTX_new", fn_name="trace_ssl_ctx_new", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_new", fn_name="trace_ssl_new", pid=args.pid)
b.attach_uprobe(name="/usr/lib/x86_64-linux-gnu/libssl.so.3", sym="SSL_free", fn_name="trace_ssl_free", pid=args.pid)

'''

def print_read_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"Read: PID={event.pid}, Timestamp={event.ts}, Comm={event.comm.decode()}, Data={event.buf[:event.buflen].decode(errors='ignore')}")

def print_write_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(Data)).contents
    print(f"Write: PID={event.pid}, Timestamp={event.ts}, Comm={event.comm.decode()}, Data={event.buf[:event.buflen].decode(errors='ignore')}")

b["read_events"].open_perf_buffer(print_read_event)
b["write_events"].open_perf_buffer(print_write_event)

print(f"Tracing read/write functions for PID {args.pid}  ctrl c to end.")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()