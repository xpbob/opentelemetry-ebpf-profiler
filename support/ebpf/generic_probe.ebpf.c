#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

static EBPF_INLINE int probe__generic(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  u64 ts = bpf_ktime_get_ns();

  return collect_trace(ctx, TRACE_PROBE, pid, tid, ts, 0);
}

// kprobe__generic serves as entry point for kprobe based profiling.
SEC("kprobe/generic")
int kprobe__generic(struct pt_regs *ctx)
{
  return probe__generic(ctx);
}

// usdt__cuda_correlation 用于挂载到 parcagpu:cuda_correlation USDT 探针。
// DTRACE_PROBE3(parcagpu, cuda_correlation, correlationId, signedCbid, name)
// 读取 USDT 参数中的 name 指针，存入 per-CPU record 的 cuda_name_ptr 字段，
// 然后复用 collect_trace 进行完整栈回溯（包括 Python 等解释器栈）。
// 在 unwind_stop 中会根据 TRACE_CUDA origin 从 cuda_name_ptr 读取 name
// 并填入 custom_labels。
SEC("kprobe/usdt_cuda")
int usdt__cuda_correlation(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  // 读取 USDT 参数：
  // arg0 = name (char* 指针)        — 栈顶
  // arg1 = correlationId (暂不使用)
  // arg2 = signedCbid    (暂不使用) — 栈底
  //
  // USDT 探针通过 uprobe 挂载时，参数不在标准的函数调用寄存器中，
  // 而是由 DTRACE_PROBE3 宏在编译时将参数位置记录在 ELF note section 中。
  // 对于 x86_64 上 GCC 编译的 SDT 探针，参数通常在栈上（相对于 rbp 的偏移）。
  // 这里通过 bpf_probe_read_user 从 ctx->bp 偏移处读取第一个参数 name（栈顶）。
  //
  // USDT 参数布局（x86_64, GCC SDT）：
  //   arg0 (name):          8@-8(%rbp)   -> rbp - 8   （栈顶）
  //   arg1 (correlationId): 8@-16(%rbp)  -> rbp - 16
  //   arg2 (signedCbid):   -8@-24(%rbp)  -> rbp - 24  （栈底）
  u64 name_ptr = 0;
#if defined(__x86_64)
  bpf_probe_read_user(&name_ptr, sizeof(name_ptr), (void *)(ctx->bp - 8));
#elif defined(__aarch64__)
  bpf_probe_read_user(&name_ptr, sizeof(name_ptr), (void *)(ctx->regs[29] - 8));
#endif

  // 将 name 指针存入 per-CPU record，供 unwind_stop 中读取。
  // 注意：get_per_cpu_record() 不会清零 cuda_name_ptr，
  // 而后续 collect_trace 内部的 get_pristine_per_cpu_record() 也不会清零它。
  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    return -1;
  }
  record->cuda_name_ptr = name_ptr;

  u64 ts = bpf_ktime_get_ns();

  // 复用 collect_trace 进行完整栈回溯，包括 native、Python、Java 等解释器栈。
  // collect_trace 内部会通过 tail_call 进入 unwinder 链，最终到达 unwind_stop。
  return collect_trace(ctx, TRACE_CUDA, pid, tid, ts, 0);
}
