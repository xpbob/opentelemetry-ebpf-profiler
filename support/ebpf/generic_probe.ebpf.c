#include "bpfdefs.h"
#include "tracemgmt.h"
#include "types.h"

// usdt_args_config 存储 USDT 探针的参数读取配置。
// key: USDT_CONFIG_CUDA_CORRELATION (0) 或 USDT_CONFIG_KERNEL_EXECUTED (1)
// value: UsdtArgsConfig 结构体，描述每个参数如何从 pt_regs 中读取。
// Go 侧在挂载 uprobe 前解析 SDT Arguments 字符串并写入此 map。
struct usdt_args_config_t {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, UsdtArgsConfig);
  __uint(max_entries, USDT_CONFIG_MAX_ENTRIES);
} usdt_args_config SEC(".maps");

// read_usdt_arg 根据 UsdtArgSpec 从 pt_regs 中读取一个 USDT 参数值。
// 返回读取到的 u64 值（小于 8 字节的参数会零扩展或符号扩展）。
static EBPF_INLINE u64 read_usdt_arg(struct pt_regs *ctx, const UsdtArgSpec *spec)
{
  if (spec->reg_offset < 0) {
    return 0;
  }

  // 从 pt_regs 中读取基址寄存器的值
  u64 reg_val = 0;
  bpf_probe_read(&reg_val, sizeof(reg_val), (void *)ctx + spec->reg_offset);

  if (spec->is_indirect) {
    // 间接寻址：reg_val 是基址，加上 mem_offset 从用户态内存读取
    u64 result = 0;
    void *addr = (void *)(reg_val + (s64)spec->mem_offset);
    switch (spec->size) {
    case 1: {
      u8 tmp = 0;
      bpf_probe_read_user(&tmp, sizeof(tmp), addr);
      result = spec->is_signed ? (u64)(s64)(s8)tmp : (u64)tmp;
      break;
    }
    case 2: {
      u16 tmp = 0;
      bpf_probe_read_user(&tmp, sizeof(tmp), addr);
      result = spec->is_signed ? (u64)(s64)(s16)tmp : (u64)tmp;
      break;
    }
    case 4: {
      u32 tmp = 0;
      bpf_probe_read_user(&tmp, sizeof(tmp), addr);
      result = spec->is_signed ? (u64)(s64)(s32)tmp : (u64)tmp;
      break;
    }
    default: // 8
      bpf_probe_read_user(&result, sizeof(result), addr);
      break;
    }
    return result;
  }

  // 直接寻址：从寄存器值中截取指定大小
  switch (spec->size) {
  case 1:
    return spec->is_signed ? (u64)(s64)(s8)(u8)reg_val : (u64)(u8)reg_val;
  case 2:
    return spec->is_signed ? (u64)(s64)(s16)(u16)reg_val : (u64)(u16)reg_val;
  case 4:
    return spec->is_signed ? (u64)(s64)(s32)(u32)reg_val : (u64)(u32)reg_val;
  default: // 8
    return reg_val;
  }
}

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
// 通过 usdt_args_config map 动态读取参数位置，支持不同编译器生成的参数布局。
// arg0 = correlationId, arg1 = signedCbid, arg2 = name (char* 指针)
SEC("kprobe/usdt_cuda")
int usdt__cuda_correlation(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  // 从 map 中读取参数配置
  u32 config_key = USDT_CONFIG_CUDA_CORRELATION;
  UsdtArgsConfig *config = bpf_map_lookup_elem(&usdt_args_config, &config_key);
  if (!config || config->num_args < 3) {
    return 0;
  }

  // arg0 = correlationId, arg2 = name (char* 指针)
  u64 correlation_id = read_usdt_arg(ctx, &config->args[0]);
  u64 name_ptr       = read_usdt_arg(ctx, &config->args[2]);

  // 将 name 指针和 correlationId 存入 per-CPU record，供 unwind_stop 中读取。
  PerCPURecord *record = get_per_cpu_record();
  if (!record) {
    return -1;
  }
  record->cuda_name_ptr = name_ptr;
  record->cuda_correlation_id = correlation_id;

  u64 ts = bpf_ktime_get_ns();

  // 复用 collect_trace 进行完整栈回溯，包括 native、Python、Java 等解释器栈。
  return collect_trace(ctx, TRACE_CUDA, pid, tid, ts, 0);
}

// usdt__kernel_executed 用于挂载到 parcagpu:kernel_executed USDT 探针。
// DTRACE_PROBE8(parcagpu, kernel_executed, start, end, correlationId,
//               deviceId, streamId, graphId, graphNodeId, name)
// 通过 usdt_args_config map 动态读取参数位置。
// arg0 = start, arg1 = end, arg2 = correlationId
SEC("kprobe/usdt_cuda_kernel_exec")
int usdt__kernel_executed(struct pt_regs *ctx)
{
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid      = pid_tgid >> 32;
  u32 tid      = pid_tgid & 0xFFFFFFFF;

  if (pid == 0 || tid == 0) {
    return 0;
  }

  // 从 map 中读取参数配置
  u32 config_key = USDT_CONFIG_KERNEL_EXECUTED;
  UsdtArgsConfig *config = bpf_map_lookup_elem(&usdt_args_config, &config_key);
  if (!config || config->num_args < 3) {
    return 0;
  }

  // arg0 = start, arg1 = end, arg2 = correlationId
  u64 start          = read_usdt_arg(ctx, &config->args[0]);
  u64 end            = read_usdt_arg(ctx, &config->args[1]);
  u64 correlation_id = read_usdt_arg(ctx, &config->args[2]);

  // 获取 per-CPU record 并初始化 trace
  PerCPURecord *record = get_pristine_per_cpu_record();
  if (!record) {
    return -1;
  }

  Trace *trace   = &record->trace;
  trace->origin  = TRACE_CUDA_KERNEL_EXEC;
  trace->pid     = pid;
  trace->tid     = tid;
  trace->ktime   = bpf_ktime_get_ns();
  trace->offtime = 0;
  if (bpf_get_current_comm(&(trace->comm), sizeof(trace->comm)) < 0) {
    increment_metric(metricID_ErrBPFCurrentComm);
  }

  // 将 correlationId、start、end 写入 custom_labels
  CustomLabelsArray *labels = &trace->custom_labels;

  // label 0: cuda_corr_id = correlationId（二进制 u64）
  if (labels->len < MAX_CUSTOM_LABELS) {
    u32 idx = labels->len;
    __builtin_memset(labels->labels[idx].key, 0, sizeof(labels->labels[idx].key));
    labels->labels[idx].key[0] = 'c';
    labels->labels[idx].key[1] = 'u';
    labels->labels[idx].key[2] = 'd';
    labels->labels[idx].key[3] = 'a';
    labels->labels[idx].key[4] = '_';
    labels->labels[idx].key[5] = 'c';
    labels->labels[idx].key[6] = 'o';
    labels->labels[idx].key[7] = 'r';
    labels->labels[idx].key[8] = 'r';
    labels->labels[idx].key[9] = '_';
    labels->labels[idx].key[10] = 'i';
    labels->labels[idx].key[11] = 'd';

    __builtin_memset(labels->labels[idx].val, 0, sizeof(labels->labels[idx].val));
    *(u64 *)labels->labels[idx].val = correlation_id;
    labels->len = idx + 1;
  }

  // label 1: cuda_start = start（二进制 u64）
  if (labels->len < MAX_CUSTOM_LABELS) {
    u32 idx = labels->len;
    __builtin_memset(labels->labels[idx].key, 0, sizeof(labels->labels[idx].key));
    labels->labels[idx].key[0] = 'c';
    labels->labels[idx].key[1] = 'u';
    labels->labels[idx].key[2] = 'd';
    labels->labels[idx].key[3] = 'a';
    labels->labels[idx].key[4] = '_';
    labels->labels[idx].key[5] = 's';
    labels->labels[idx].key[6] = 't';
    labels->labels[idx].key[7] = 'a';
    labels->labels[idx].key[8] = 'r';
    labels->labels[idx].key[9] = 't';

    __builtin_memset(labels->labels[idx].val, 0, sizeof(labels->labels[idx].val));
    *(u64 *)labels->labels[idx].val = start;
    labels->len = idx + 1;
  }

  // label 2: cuda_end = end（二进制 u64）
  if (labels->len < MAX_CUSTOM_LABELS) {
    u32 idx = labels->len;
    __builtin_memset(labels->labels[idx].key, 0, sizeof(labels->labels[idx].key));
    labels->labels[idx].key[0] = 'c';
    labels->labels[idx].key[1] = 'u';
    labels->labels[idx].key[2] = 'd';
    labels->labels[idx].key[3] = 'a';
    labels->labels[idx].key[4] = '_';
    labels->labels[idx].key[5] = 'e';
    labels->labels[idx].key[6] = 'n';
    labels->labels[idx].key[7] = 'd';

    __builtin_memset(labels->labels[idx].val, 0, sizeof(labels->labels[idx].val));
    *(u64 *)labels->labels[idx].val = end;
    labels->len = idx + 1;
  }

  // 不做栈回溯，直接发送 trace
  send_trace(ctx, trace);
  return 0;
}
