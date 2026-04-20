// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"fmt"
	"os"
	"time"

	pprofProfile "github.com/google/pprof/profile"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// pprofWriter 将采样数据转换为 pprof 格式（profile.proto）。
// pprof 是 Go 生态中广泛使用的性能剖析格式，可被 go tool pprof、
// pprof 命令行工具、FlameScope、Grafana Pyroscope 等工具解析。
type pprofWriter struct {
	// 采样开始时间
	startTime time.Time

	// 采样频率（Hz）
	samplesPerSecond int

	// enableTime 开启后，将 CPU 采样的采样次数转换为时间
	enableTime bool

	// timeUnit 时间转化单位
	timeUnit support.TimeUnit

	// 去重用的 map
	functionMap  map[string]*pprofProfile.Function // funcKey -> Function
	locationMap  map[string]*pprofProfile.Location  // locKey -> Location

	// ID 计数器
	nextFunctionID uint64
	nextLocationID uint64
}

// newPprofWriter 创建一个新的 pprofWriter 实例。
func newPprofWriter(startTime time.Time, samplesPerSecond int, enableTime bool, timeUnit support.TimeUnit) *pprofWriter {
	return &pprofWriter{
		startTime:        startTime,
		samplesPerSecond: samplesPerSecond,
		enableTime:       enableTime,
		timeUnit:         timeUnit,
		functionMap:      make(map[string]*pprofProfile.Function),
		locationMap:      make(map[string]*pprofProfile.Location),
		nextFunctionID:   1,
		nextLocationID:   1,
	}
}

// getOrCreateFunction 获取或创建一个 pprof Function。
func (w *pprofWriter) getOrCreateFunction(name, filename string) *pprofProfile.Function {
	key := fmt.Sprintf("%s@%s", name, filename)
	if fn, ok := w.functionMap[key]; ok {
		return fn
	}
	fn := &pprofProfile.Function{
		ID:       w.nextFunctionID,
		Name:     name,
		Filename: filename,
	}
	w.nextFunctionID++
	w.functionMap[key] = fn
	return fn
}

// getOrCreateLocation 获取或创建一个 pprof Location。
func (w *pprofWriter) getOrCreateLocation(fn *pprofProfile.Function, line int64) *pprofProfile.Location {
	key := fmt.Sprintf("%d:%d", fn.ID, line)
	if loc, ok := w.locationMap[key]; ok {
		return loc
	}
	loc := &pprofProfile.Location{
		ID: w.nextLocationID,
		Line: []pprofProfile.Line{
			{
				Function: fn,
				Line:     line,
			},
		},
	}
	w.nextLocationID++
	w.locationMap[key] = loc
	return loc
}

// buildProfile 将 TraceEventsTree 转换为 pprof Profile。
func (w *pprofWriter) buildProfile(reportedEvents samples.TraceEventsTree, durationNanos int64) *pprofProfile.Profile {
	prof := &pprofProfile.Profile{
		SampleType: []*pprofProfile.ValueType{
			{
				Type: "cpu",
				Unit: "nanoseconds",
			},
			{
				Type: "samples",
				Unit: "count",
			},
		},
		PeriodType: &pprofProfile.ValueType{
			Type: "cpu",
			Unit: "nanoseconds",
		},
		TimeNanos:     w.startTime.UnixNano(),
		DurationNanos: durationNanos,
	}

	// 采样周期（纳秒）
	if w.samplesPerSecond > 0 {
		prof.Period = int64(time.Second) / int64(w.samplesPerSecond)
	}

	// 遍历所有采样事件
	for resourceKey, resourceToProfiles := range reportedEvents {
		// 为每个资源（进程）创建一个 ELF 符号解析器
		var resolver *elfSymbolResolver
		if resourceKey.PID > 0 {
			resolver = newElfSymbolResolver(resourceKey.PID)
		}

		for origin, sampleToEvents := range resourceToProfiles.Events {
			for sampleKey, traceEvents := range sampleToEvents {
				if traceEvents == nil || len(traceEvents.Timestamps) == 0 {
					continue
				}

				// 构建 Location 列表（pprof 中栈帧从叶子到根排列）
				locations := w.buildLocations(traceEvents.Frames, resolver)

				// 采样次数
				count := int64(len(traceEvents.Timestamps))

				// 计算 CPU 时间值
				var cpuNanos int64
				if w.enableTime && origin == support.TraceOriginSampling &&
					w.samplesPerSecond > 0 {
					// enableTime 开启且为 CPU 采样：将采样次数转换为纳秒
					cpuNanos = count * (int64(time.Second) / int64(w.samplesPerSecond))
				} else if origin == support.TraceOriginSampling && w.samplesPerSecond > 0 {
					cpuNanos = count * (int64(time.Second) / int64(w.samplesPerSecond))
				} else if origin == support.TraceOriginCuda {
					// CUDA 的 GPU 执行时间以纳秒存储在 GpuDurationNs 中
					cpuNanos = traceEvents.GpuDurationNs
				}

				sample := &pprofProfile.Sample{
					Location: locations,
					Value:    []int64{cpuNanos, count},
					Label: map[string][]string{
						"thread": {sampleKey.Comm.String()},
					},
				}

				// 添加 TID 标签
				if sampleKey.TID > 0 {
					sample.NumLabel = map[string][]int64{
						"tid": {sampleKey.TID},
					}
				}

				prof.Sample = append(prof.Sample, sample)
			}
		}
	}

	// 收集所有 Function 和 Location
	for _, fn := range w.functionMap {
		prof.Function = append(prof.Function, fn)
	}
	for _, loc := range w.locationMap {
		prof.Location = append(prof.Location, loc)
	}

	return prof
}

// buildLocations 将 eBPF 采集的栈帧转换为 pprof Location 列表。
// eBPF 采集的栈帧顺序是从叶子到根，pprof 也是从叶子到根（index 0 = leaf）。
// resolver 可以为 nil，此时不进行本地 ELF 符号化。
func (w *pprofWriter) buildLocations(frames libpf.Frames, resolver *elfSymbolResolver) []*pprofProfile.Location {
	locations := make([]*pprofProfile.Location, 0, len(frames))

	for _, frameHandle := range frames {
		frame := frameHandle.Value()

		var funcName, fileName string
		var lineNumber int64

		if frame.Type.IsError() {
			if frame.Type.IsAbort() {
				funcName = fmt.Sprintf("[abort:0x%x]", frame.AddressOrLineno)
			} else {
				funcName = fmt.Sprintf("[error:0x%x]", frame.AddressOrLineno)
			}
			fileName = "[error]"
		} else if frame.FunctionName != libpf.NullString {
			funcName = frame.FunctionName.String()
			if frame.SourceFile != libpf.NullString {
				fileName = frame.SourceFile.String()
			}
			if frame.SourceLine > 0 {
				lineNumber = int64(frame.SourceLine)
			}
		} else if frame.Mapping.Valid() {
			mf := frame.Mapping.Value().File.Value()
			mfName := mf.FileName.String()
			fileName = mfName

			// 尝试通过 ELF 符号表解析函数名
			if resolver != nil && mfName != "" {
				if resolved := resolver.resolve(mfName, uint64(frame.AddressOrLineno)); resolved != "" {
					funcName = resolved
				} else {
					funcName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
				}
			} else {
				funcName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
			}
		} else {
			funcName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
			fileName = "[unknown]"
		}

		fn := w.getOrCreateFunction(funcName, fileName)
		loc := w.getOrCreateLocation(fn, lineNumber)
		locations = append(locations, loc)
	}

	return locations
}

// writePprofFile 将采样数据以 pprof 格式写入文件。
func (w *pprofWriter) writePprofFile(outputFile string, reportedEvents samples.TraceEventsTree, durationNanos int64) error {
	prof := w.buildProfile(reportedEvents, durationNanos)

	// 校验 profile 数据
	if err := prof.CheckValid(); err != nil {
		return fmt.Errorf("pprof profile 数据校验失败: %v", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建 pprof 文件 %s 失败: %v", outputFile, err)
	}
	defer f.Close()

	// Write 方法会自动进行 gzip 压缩
	if err := prof.Write(f); err != nil {
		return fmt.Errorf("写入 pprof 数据失败: %v", err)
	}

	totalSamples := int64(0)
	for _, s := range prof.Sample {
		if len(s.Value) >= 2 {
			totalSamples += s.Value[1]
		}
	}

	log.Infof("pprof 文件已写入: %s (共 %d 个采样, %d 个唯一栈帧, %d 个函数)",
		outputFile, totalSamples, len(prof.Location), len(prof.Function))

	return nil
}
