// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// FileType 定义输出文件格式类型。
type FileType string

const (
	// FileTypeFolded 表示 Linux folded 格式，可直接用 flamegraph.pl 生成火焰图。
	FileTypeFolded FileType = "folded"
	// FileTypeJFR 表示 JDK Flight Recorder 格式，可用 JMC 或 jfr 命令行工具解析。
	FileTypeJFR FileType = "jfr"
	// FileTypePprof 表示 pprof 格式（profile.proto），可用 go tool pprof 或 pprof 命令行工具解析。
	FileTypePprof FileType = "pprof"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*FileReporter)(nil)

// FileReporter 收集 profiling 数据并在停止时将结果写入本地文件。
// 支持按 PID 过滤，只收集目标进程的堆栈数据。
// 通过 fileType 选择输出格式：folded（默认）、jfr 或 pprof。
type FileReporter struct {
	*baseReporter

	// targetPID 是要采集的目标进程 PID，0 表示不过滤（采集所有进程）。
	targetPID libpf.PID

	// outputFile 是输出结果文件的路径。
	outputFile string

	// fileType 是输出文件格式类型（folded、jfr 或 pprof）。
	fileType FileType
}

// NewFileReporter 创建一个新的 FileReporter 实例。
// targetPID 为 0 时不进行 PID 过滤。
// fileType 指定输出格式："folded"（默认）、"jfr" 或 "pprof"。
func NewFileReporter(cfg *Config, targetPID int, outputFile string, fileType FileType) (*FileReporter, error) {
	// 校验 fileType，默认为 folded
	if fileType == "" {
		fileType = FileTypeFolded
	}
	if fileType != FileTypeFolded && fileType != FileTypeJFR && fileType != FileTypePprof {
		return nil, fmt.Errorf("不支持的文件格式: %s，支持的格式: folded, jfr, pprof", fileType)
	}
	data, err := pdata.New(
		cfg.SamplesPerSecond,
		cfg.ExtraSampleAttrProd,
	)
	if err != nil {
		return nil, err
	}

	eventsTree := make(samples.TraceEventsTree)

	return &FileReporter{
		baseReporter: &baseReporter{
			cfg:         cfg,
			name:        cfg.Name,
			version:     cfg.Version,
			pdata:       data,
			traceEvents: xsync.NewRWMutex(eventsTree),
			runLoop: &runLoop{
				stopSignal: make(chan libpf.Void),
			},
		},
		targetPID:  libpf.PID(targetPID),
		outputFile: outputFile,
		fileType:   fileType,
	}, nil
}

// Start 启动 FileReporter。
func (r *FileReporter) Start(_ context.Context) error {
	r.collectionStartTime = time.Now()
	log.Infof("FileReporter 已启动，目标 PID: %d，输出文件: %s，格式: %s",
		r.targetPID, r.outputFile, r.fileType)
	return nil
}

// Stop 停止 FileReporter 并将收集到的数据写入文件。
func (r *FileReporter) Stop() {
	log.Infof("FileReporter 正在停止，开始生成 %s 格式结果文件...", r.fileType)

	var err error
	switch r.fileType {
	case FileTypeJFR:
		err = r.writeJFROutputFile()
	case FileTypePprof:
		err = r.writePprofOutputFile()
	default:
		err = r.writeOutputFile()
	}

	if err != nil {
		log.Errorf("写入结果文件失败: %v", err)
	} else {
		log.Infof("结果文件已写入: %s (格式: %s)", r.outputFile, r.fileType)
	}

	r.runLoop.Stop()
}

// ReportTraceEvent 接收 trace 事件，如果设置了目标 PID 则进行过滤。
func (r *FileReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	// 如果设置了目标 PID，过滤掉非目标进程的 trace
	if r.targetPID != 0 && meta.PID != r.targetPID {
		return nil
	}

	return r.baseReporter.ReportTraceEvent(trace, meta)
}

// formatFrame 将单个栈帧格式化为可读字符串。
// 优先使用函数名，如果没有函数名则使用 mapping 文件名+偏移，最后使用地址。
func formatFrame(frame *libpf.Frame) string {
	if frame.Type.IsError() {
		if frame.Type.IsAbort() {
			return fmt.Sprintf("[abort:0x%x]", frame.AddressOrLineno)
		}
		return fmt.Sprintf("[error:0x%x]", frame.AddressOrLineno)
	}

	if frame.FunctionName != libpf.NullString {
		name := frame.FunctionName.String()
		if frame.SourceFile != libpf.NullString && frame.SourceLine > 0 {
			return fmt.Sprintf("%s (%s:%d)", name, frame.SourceFile, frame.SourceLine)
		}
		return name
	}

	if frame.Mapping.Valid() {
		mf := frame.Mapping.Value().File.Value()
		return fmt.Sprintf("%s+0x%x", mf.FileName, frame.AddressOrLineno)
	}

	return fmt.Sprintf("0x%x", frame.AddressOrLineno)
}

// writeOutputFile 将收集到的所有 profile 数据以 Linux folded 格式写入文件。
// folded 格式: 每行为 "comm;frame1;frame2;...;frameN count"
// 栈帧顺序为从根到叶子（root → leaf），与 flamegraph.pl 的输入格式一致。
func (r *FileReporter) writeOutputFile() error {
	traceEventsPtr := r.traceEvents.WLock()
	reportedEvents := (*traceEventsPtr)
	r.traceEvents.WUnlock(&traceEventsPtr)

	f, err := os.Create(r.outputFile)
	if err != nil {
		return fmt.Errorf("创建文件 %s 失败: %v", r.outputFile, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	totalSamples := 0
	totalStacks := 0

	// 遍历所有资源和事件，生成 folded 格式输出
	for _, resourceToProfiles := range reportedEvents {
		for _, sampleToEvents := range resourceToProfiles.Events {
			for sampleKey, traceEvents := range sampleToEvents {
				if traceEvents == nil || len(traceEvents.Timestamps) == 0 {
					continue
				}

				// 采样次数 = Timestamps 的长度
				count := len(traceEvents.Timestamps)

				// 构建栈帧列表（eBPF 采集的栈帧是从叶子到根，需要反转为从根到叶子）
				frames := traceEvents.Frames
				frameStrs := make([]string, 0, len(frames))
				for i := len(frames) - 1; i >= 0; i-- {
					frame := frames[i].Value()
					frameStrs = append(frameStrs, formatFrame(&frame))
				}

				// 构建 folded 行: "comm;frame1;frame2;...;frameN count"
				// 以进程的 comm（线程名）作为栈的根
				comm := sampleKey.Comm.String()
				if comm == "" {
					comm = "[unknown]"
				}

				var line string
				if len(frameStrs) > 0 {
					line = fmt.Sprintf("%s;%s %d\n", comm,
						strings.Join(frameStrs, ";"), count)
				} else {
					line = fmt.Sprintf("%s %d\n", comm, count)
				}

				if _, err := w.WriteString(line); err != nil {
					return fmt.Errorf("写入 folded 数据失败: %v", err)
				}

				totalStacks++
				totalSamples += count
			}
		}
	}

	log.Infof("共收集到 %d 个唯一堆栈，%d 个采样样本", totalStacks, totalSamples)

	if totalSamples == 0 {
		log.Warnf("未收集到任何采样数据，结果文件为空")
	}

	return nil
}

// writePprofOutputFile 将收集到的所有 profile 数据以 pprof 格式写入文件。
// 生成的 .pb.gz 文件可以被 go tool pprof 或 pprof 命令行工具解析。
func (r *FileReporter) writePprofOutputFile() error {
	traceEventsPtr := r.traceEvents.WLock()
	reportedEvents := (*traceEventsPtr)
	r.traceEvents.WUnlock(&traceEventsPtr)

	duration := time.Since(r.collectionStartTime)
	pw := newPprofWriter(r.collectionStartTime, r.cfg.SamplesPerSecond)

	return pw.writePprofFile(r.outputFile, reportedEvents, duration.Nanoseconds())
}

// writeJFROutputFile 将收集到的所有 profile 数据以 JFR 格式写入文件。
// 生成的 .jfr 文件可以被 JDK Mission Control (JMC) 或 jfr 命令行工具解析。
func (r *FileReporter) writeJFROutputFile() error {
	traceEventsPtr := r.traceEvents.WLock()
	reportedEvents := (*traceEventsPtr)
	r.traceEvents.WUnlock(&traceEventsPtr)

	jw := newJFRWriter(r.collectionStartTime)
	jw.addSamples(reportedEvents)

	return jw.writeJFRFile(r.outputFile)
}
