// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"sync"
	"sync/atomic"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	eim "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// elfInfo contains cached data from an executable needed for processing mappings.
// A negative cache entry may also be recorded with err set to indicate permanent
// error. This avoids inspection of non-ELF or corrupted files again and again.
type elfInfo struct {
	err           error
	lastModified  int64
	mappingFile   libpf.FrameMappingFile
	addressMapper pfelf.AddressMapper
}

// frameCacheKey is the LRU cache key for caching frames.
type frameCacheKey struct {
	// pid is the PID of the process if the frame had FRAME_FLAG_PID_SPECIFIC set
	pid libpf.PID
	// data is the frame data: frame header and the two first variable fields
	data [3]uint64
}

// pendingCudaCorrelation 保存 cuda_correlation 触发时的栈帧和元数据，
// 等待 kernel_executed 触发时根据 correlationId 进行关联。
type pendingCudaCorrelation struct {
	// trace 是 cuda_correlation 触发时采集的完整栈帧。
	trace *libpf.Trace
	// meta 是 trace 的元数据。
	meta *samples.TraceEventMeta
	// timestampMs 是 cuda_correlation 触发时的 13 位毫秒时间戳。
	timestampMs int64
	// cudaName 是 CUDA kernel 的名称。
	cudaName string
}

// pendingKernelExecuted 保存 kernel_executed 先于 cuda_correlation 到达时的数据，
// 等待对应的 cuda_correlation 到达后进行反向匹配。
type pendingKernelExecuted struct {
	// start 是 GPU kernel 执行的起始时间戳（纳秒）。
	start uint64
	// end 是 GPU kernel 执行的结束时间戳（纳秒）。
	end uint64
	// deviceId 是 GPU 设备 ID，用于构造 [GPU<deviceId>] 栈顶帧。
	deviceId uint64
	// timestampMs 是 kernel_executed 到达时的 13 位毫秒时间戳，用于超时清理。
	timestampMs int64
}

// ProcessManager is responsible for managing the events happening throughout the lifespan of a
// process.
type ProcessManager struct {
	// A mutex to synchronize access to internal data within this struct.
	mu sync.RWMutex

	// interpreterTracerEnabled indicates if at last one non-native tracer is loaded.
	interpreterTracerEnabled bool

	// eim stores per executable (file ID) information.
	eim *eim.ExecutableInfoManager

	// interpreters records the interpreter.Instance interface which contains hooks for
	// process exits, and various other situations needing interpreter specific attention.
	// The key of the first map is a process ID, while the key of the second map is
	// the unique on-disk identifier of the interpreter DSO.
	interpreters map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance

	// pidToProcessInfo keeps track of the executable memory mappings.
	pidToProcessInfo map[libpf.PID]*processInfo

	// exitEvents records the pid exit time and is a list of pending exit events to be handled.
	exitEvents map[libpf.PID]times.KTime

	// ebpf contains the interface to manipulate ebpf maps
	ebpf pmebpf.EbpfHandler

	// elfInfoCacheHit
	elfInfoCacheHit  atomic.Uint64
	elfInfoCacheMiss atomic.Uint64

	// frame conversion
	frameCacheHit  atomic.Uint64
	frameCacheMiss atomic.Uint64

	// mappingStats are statistics for parsing process mappings
	mappingStats struct {
		errProcNotExist    atomic.Uint32
		errProcESRCH       atomic.Uint32
		errProcPerm        atomic.Uint32
		numProcAttempts    atomic.Uint32
		maxProcParseUsec   atomic.Uint32
		totalProcParseUsec atomic.Uint32
		numProcParseErrors atomic.Uint32
	}

	// elfInfoCache provides a cache to quickly retrieve the ELF info and fileID for a particular
	// executable. It caches results based on iNode number and device ID. Locked LRU.
	elfInfoCache *lru.LRU[util.OnDiskFileIdentifier, elfInfo]

	// frameCache stores mappings from BPF frame to the symbolized frames.
	// This allows avoiding the overhead of re-doing user-mode symbolization
	// of frames that we have recently seen already.
	frameCache *lru.LRU[frameCacheKey, libpf.Frames]

	// traceReporter is the interface to report traces
	traceReporter reporter.TraceReporter

	// exeReporter is the interface to report executables
	exeReporter reporter.ExecutableReporter

	// Reporting function which is used to report information to our backend.
	metricsAddSlice func([]metrics.Metric)

	// pidPageToMappingInfoSize reflects the current size of the eBPF hash map
	// pid_page_to_mapping_info.
	pidPageToMappingInfoSize uint64

	// filterErrorFrames determines whether error frames are dropped by `ConvertTrace`.
	filterErrorFrames bool

	// includeEnvVars holds a list of env vars that should be captured from processes
	includeEnvVars libpf.Set[string]

	// pendingCudaCorrelations 保存 cuda_correlation 触发但尚未匹配 kernel_executed 的记录。
	// key 是 correlationId（uint64）。
	pendingCudaCorrelations map[uint64]*pendingCudaCorrelation

	// pendingKernelExecuted 保存 kernel_executed 先于 cuda_correlation 到达时的数据。
	// key 是 correlationId（uint64）。
	pendingKernelExecuted map[uint64]*pendingKernelExecuted
}

// Mapping represents an executable memory mapping of a process.
type Mapping struct {
	// Vaddr represents the starting virtual address of the mapping.
	Vaddr libpf.Address

	// Length is the length of the mapping
	Length uint64

	// Device number of the backing file
	Device uint64

	// Inode number of the backing file
	Inode uint64

	// FrameMapping data for this mapping.
	FrameMapping libpf.FrameMapping
}

// GetOnDiskFileIdentifier returns the OnDiskFileIdentifier for the mapping
func (m *Mapping) GetOnDiskFileIdentifier() util.OnDiskFileIdentifier {
	return util.OnDiskFileIdentifier{
		DeviceID: m.Device,
		InodeNum: m.Inode,
	}
}

// processInfo contains information about the executable mappings
// and Thread Specific Data of a process.
type processInfo struct {
	// process metadata, fixed for process lifetime (read-only)
	meta process.ProcessMeta
	// executable mappings sorted by FileID and mapping start address
	mappings []Mapping
	// C-library Thread Specific Data information
	libcInfo *libc.LibcInfo
}
