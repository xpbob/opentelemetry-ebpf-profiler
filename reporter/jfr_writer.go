// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// JFR 文件格式常量
const (
	// JFR 文件魔数: "FLR\0"
	jfrMagic = 0x464c5200

	// JFR 版本号 (JDK 11+: major=2, minor=0)
	jfrVersionMajor = 2
	jfrVersionMinor = 0

	// JFR 事件类型 ID（自定义，需与 metadata 中的定义一致）
	jfrEventTypeCheckpoint     = 1
	jfrEventTypeMetadata       = 0
	jfrEventTypeExecutionSample = 100
	jfrEventTypeThreadInfo     = 101
	jfrEventTypeStackTrace     = 102
	jfrEventTypeMethod         = 103
	jfrEventTypeClass          = 104
	jfrEventTypePackage        = 105
	jfrEventTypeSymbol         = 106
	jfrEventTypeFrameType      = 107
	jfrEventTypeThreadState    = 108

	// 常量池类型 ID
	jfrTypeThread     = 200
	jfrTypeStackTrace = 201
	jfrTypeMethod     = 202
	jfrTypeClass      = 203
	jfrTypePackage    = 204
	jfrTypeSymbol     = 205
	jfrTypeFrameType  = 206
	jfrTypeThreadState = 207
)

// jfrWriter 负责将 profiling 数据写入 JFR 格式文件。
type jfrWriter struct {
	// 常量池：用于去重和引用
	symbols    map[string]int64 // 字符串 -> symbol ID
	methods    map[string]int64 // 方法签名 -> method ID
	classes    map[string]int64 // 类名 -> class ID
	packages   map[string]int64 // 包名 -> package ID
	threads    map[string]int64 // 线程名 -> thread ID
	stackTraces map[string]int64 // 栈帧组合 -> stackTrace ID
	frameTypes map[string]int64 // 帧类型 -> frameType ID

	// 栈帧数据：stackTrace ID -> 帧列表
	stackTraceFrames map[int64][]jfrStackFrame

	// ID 计数器
	nextSymbolID     int64
	nextMethodID     int64
	nextClassID      int64
	nextPackageID    int64
	nextThreadID     int64
	nextStackTraceID int64
	nextFrameTypeID  int64

	// 采样数据
	executionSamples []jfrExecutionSample

	// 时间信息
	startTime time.Time
	startTick int64
	tickFreq  int64 // 纳秒/tick
}

// jfrExecutionSample 表示一个 CPU 采样事件。
type jfrExecutionSample struct {
	timestamp    int64 // 纳秒时间戳
	threadID     int64
	stackTraceID int64
	state        int64 // 线程状态
}

// jfrStackFrame 表示 JFR 中的一个栈帧。
type jfrStackFrame struct {
	methodID    int64
	lineNumber  int32
	bytecodeIdx int32
	frameTypeID int64
}

// newJFRWriter 创建一个新的 JFR 写入器。
func newJFRWriter(startTime time.Time) *jfrWriter {
	w := &jfrWriter{
		symbols:         make(map[string]int64),
		methods:         make(map[string]int64),
		classes:         make(map[string]int64),
		packages:        make(map[string]int64),
		threads:         make(map[string]int64),
		stackTraces:     make(map[string]int64),
		stackTraceFrames: make(map[int64][]jfrStackFrame),
		frameTypes:      make(map[string]int64),
		startTime:   startTime,
		startTick:   startTime.UnixNano(),
		tickFreq:    1, // 1 tick = 1 纳秒
	}

	// 预注册默认符号
	w.getOrCreateSymbol("")
	// 预注册默认帧类型
	w.getOrCreateFrameType("Interpreted")
	w.getOrCreateFrameType("JIT compiled")
	w.getOrCreateFrameType("Inlined")
	w.getOrCreateFrameType("Native")
	w.getOrCreateFrameType("C++")

	return w
}

// getOrCreateSymbol 获取或创建一个符号 ID。
func (w *jfrWriter) getOrCreateSymbol(s string) int64 {
	if id, ok := w.symbols[s]; ok {
		return id
	}
	id := w.nextSymbolID
	w.symbols[s] = id
	w.nextSymbolID++
	return id
}

// getOrCreateFrameType 获取或创建一个帧类型 ID。
func (w *jfrWriter) getOrCreateFrameType(name string) int64 {
	if id, ok := w.frameTypes[name]; ok {
		return id
	}
	id := w.nextFrameTypeID
	w.frameTypes[name] = id
	w.nextFrameTypeID++
	return id
}

// getOrCreatePackage 获取或创建一个包 ID。
func (w *jfrWriter) getOrCreatePackage(name string) int64 {
	if id, ok := w.packages[name]; ok {
		return id
	}
	id := w.nextPackageID
	w.packages[name] = id
	w.nextPackageID++
	return id
}

// getOrCreateClass 获取或创建一个类 ID。
func (w *jfrWriter) getOrCreateClass(name string) int64 {
	if id, ok := w.classes[name]; ok {
		return id
	}
	id := w.nextClassID
	w.classes[name] = id
	w.nextClassID++
	return id
}

// getOrCreateMethod 获取或创建一个方法 ID。
func (w *jfrWriter) getOrCreateMethod(className, methodName, descriptor string) int64 {
	key := className + "." + methodName + descriptor
	if id, ok := w.methods[key]; ok {
		return id
	}
	id := w.nextMethodID
	w.methods[key] = id
	w.nextMethodID++
	return id
}

// getOrCreateThread 获取或创建一个线程 ID。
func (w *jfrWriter) getOrCreateThread(name string) int64 {
	if id, ok := w.threads[name]; ok {
		return id
	}
	id := w.nextThreadID + 1 // 线程 ID 从 1 开始
	w.threads[name] = id
	w.nextThreadID++
	return id
}

// addSamples 将 profiling 数据转换为 JFR 采样事件。
func (w *jfrWriter) addSamples(reportedEvents samples.TraceEventsTree) {
	for _, resourceToProfiles := range reportedEvents {
		for _, sampleToEvents := range resourceToProfiles.Events {
			for sampleKey, traceEvents := range sampleToEvents {
				if traceEvents == nil || len(traceEvents.Timestamps) == 0 {
					continue
				}

				// 获取线程 ID
				comm := sampleKey.Comm.String()
				if comm == "" {
					comm = "[unknown]"
				}
				threadID := w.getOrCreateThread(comm)

				// 构建栈帧并获取 stackTrace ID
				stackTraceID := w.buildStackTrace(traceEvents.Frames)

				// 为每个采样时间戳创建一个 ExecutionSample 事件
				for _, ts := range traceEvents.Timestamps {
					w.executionSamples = append(w.executionSamples, jfrExecutionSample{
						timestamp:    int64(ts),
						threadID:     threadID,
						stackTraceID: stackTraceID,
						state:        0, // STATE_RUNNABLE
					})
				}
			}
		}
	}
}

// buildStackTrace 将 eBPF 栈帧转换为 JFR 栈帧，并返回 stackTrace ID。
func (w *jfrWriter) buildStackTrace(frames libpf.Frames) int64 {
	// 构建栈帧的唯一 key
	var keyBuf bytes.Buffer
	jfrFrames := make([]jfrStackFrame, 0, len(frames))

	// eBPF 采集的栈帧是从叶子到根，JFR 也是从叶子到根（top frame first）
	for _, frameHandle := range frames {
		frame := frameHandle.Value()

		var className, methodName, sourceFile string
		var lineNumber int32
		var frameTypeName string

		if frame.Type.IsError() {
			className = "[error]"
			methodName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
			frameTypeName = "Native"
		} else if frame.FunctionName != libpf.NullString {
			methodName = frame.FunctionName.String()
			if frame.SourceFile != libpf.NullString {
				sourceFile = frame.SourceFile.String()
				className = sourceFile
			} else {
				className = "[unknown]"
			}
			if frame.SourceLine > 0 {
				lineNumber = int32(frame.SourceLine)
			}
			// 根据帧类型选择 JFR 帧类型
			frameTypeName = w.mapFrameType(frame.Type)
		} else if frame.Mapping.Valid() {
			mf := frame.Mapping.Value().File.Value()
			className = mf.FileName.String()
			methodName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
			frameTypeName = "Native"
		} else {
			className = "[unknown]"
			methodName = fmt.Sprintf("0x%x", frame.AddressOrLineno)
			frameTypeName = "Native"
		}

		// 确保符号已注册
		w.getOrCreateSymbol(sourceFile)

		classID := w.getOrCreateClass(className)
		methodID := w.getOrCreateMethod(className, methodName, "()V")
		frameTypeID := w.getOrCreateFrameType(frameTypeName)

		jfrFrames = append(jfrFrames, jfrStackFrame{
			methodID:    methodID,
			lineNumber:  lineNumber,
			bytecodeIdx: 0,
			frameTypeID: frameTypeID,
		})

		fmt.Fprintf(&keyBuf, "%d:%d:%d;", classID, methodID, lineNumber)
	}

	key := keyBuf.String()
	if id, ok := w.stackTraces[key]; ok {
		return id
	}

	id := w.nextStackTraceID
	w.stackTraces[key] = id
	// 保存栈帧数据，供写入常量池时使用
	w.stackTraceFrames[id] = jfrFrames
	w.nextStackTraceID++

	return id
}

// mapFrameType 将 eBPF 帧类型映射为 JFR 帧类型名称。
func (w *jfrWriter) mapFrameType(ft libpf.FrameType) string {
	switch ft {
	case libpf.NativeFrame:
		return "Native"
	case libpf.KernelFrame:
		return "Native"
	case libpf.HotSpotFrame:
		return "JIT compiled"
	case libpf.PythonFrame, libpf.RubyFrame, libpf.PerlFrame,
		libpf.PHPFrame, libpf.V8Frame, libpf.DotnetFrame, libpf.BEAMFrame:
		return "Interpreted"
	case libpf.GoFrame:
		return "Native"
	default:
		return "Native"
	}
}

// writeJFRFile 将所有数据写入 JFR 文件。
func (w *jfrWriter) writeJFRFile(outputFile string) error {
	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("创建 JFR 文件 %s 失败: %v", outputFile, err)
	}
	defer f.Close()

	// 生成 chunk 数据
	chunkData, err := w.buildChunk()
	if err != nil {
		return fmt.Errorf("构建 JFR chunk 失败: %v", err)
	}

	_, err = f.Write(chunkData)
	if err != nil {
		return fmt.Errorf("写入 JFR 数据失败: %v", err)
	}

	log.Infof("JFR 文件已写入: %s (共 %d 个采样事件, %d 个唯一栈帧)",
		outputFile, len(w.executionSamples), len(w.stackTraces))

	return nil
}

// buildChunk 构建一个完整的 JFR chunk。
func (w *jfrWriter) buildChunk() ([]byte, error) {
	// 1. 构建事件数据（body）
	bodyBuf := &bytes.Buffer{}

	// 写入 ExecutionSample 事件
	for _, sample := range w.executionSamples {
		w.writeExecutionSampleEvent(bodyBuf, &sample)
	}

	// 2. 构建常量池（checkpoint 事件）
	cpBuf := &bytes.Buffer{}
	w.writeCheckpointEvent(cpBuf)

	// 3. 构建 metadata 事件
	metaBuf := &bytes.Buffer{}
	w.writeMetadataEvent(metaBuf)

	// 4. 计算各部分偏移和总大小
	headerSize := int64(68) // JFR chunk header 固定 68 字节
	bodySize := int64(bodyBuf.Len())
	cpOffset := headerSize + bodySize
	cpSize := int64(cpBuf.Len())
	metaOffset := cpOffset + cpSize
	metaSize := int64(metaBuf.Len())
	chunkSize := headerSize + bodySize + cpSize + metaSize

	// 5. 构建 chunk header (68 字节)
	// JFR v2.0 Chunk Header 布局 (参考 JDK 17 ChunkHeader.java):
	// [0..3]   magic "FLR\0"
	// [4..5]   major version
	// [6..7]   minor version
	// [8..15]  chunk size (CHUNK_SIZE_POSITION = 8)
	// [16..23] constant pool offset
	// [24..31] metadata offset
	// [32..39] start time nanos (wall clock, epoch nanos)
	// [40..47] duration nanos (DURATION_NANOS_POSITION = 40)
	// [48..55] start ticks
	// [56..63] ticks per second
	// [64]     file state (FILE_STATE_POSITION = 64, 0 = finished)
	// [65..66] 保留
	// [67]     flag byte (FLAG_BYTE_POSITION = 67, bit 1 = final chunk)
	headerBuf := &bytes.Buffer{}
	binary.Write(headerBuf, binary.BigEndian, uint32(jfrMagic))
	binary.Write(headerBuf, binary.BigEndian, uint16(jfrVersionMajor))
	binary.Write(headerBuf, binary.BigEndian, uint16(jfrVersionMinor))
	binary.Write(headerBuf, binary.BigEndian, int64(chunkSize))
	binary.Write(headerBuf, binary.BigEndian, int64(cpOffset))
	binary.Write(headerBuf, binary.BigEndian, int64(metaOffset))
	// start time nanos (wall clock)
	binary.Write(headerBuf, binary.BigEndian, int64(w.startTime.UnixNano()))
	// duration nanos
	duration := time.Since(w.startTime).Nanoseconds()
	binary.Write(headerBuf, binary.BigEndian, int64(duration))
	// start ticks
	binary.Write(headerBuf, binary.BigEndian, int64(w.startTick))
	// ticks per second
	binary.Write(headerBuf, binary.BigEndian, int64(1_000_000_000))
	// [64] file state = 0 (finished)
	// [65..66] 保留 = 0
	// [67] flag byte: bit 1 = final chunk
	headerBuf.Write([]byte{0x00, 0x00, 0x00, 0x02})

	// 6. 组装完整 chunk
	result := make([]byte, 0, chunkSize)
	result = append(result, headerBuf.Bytes()...)
	result = append(result, bodyBuf.Bytes()...)
	result = append(result, cpBuf.Bytes()...)
	result = append(result, metaBuf.Bytes()...)

	return result, nil
}

// writeCompressedInt 写入 LEB128 编码的压缩整数（JFR 使用的变长编码）。
func writeCompressedInt(w io.Writer, val int64) {
	uval := uint64(val)
	for {
		b := byte(uval & 0x7f)
		uval >>= 7
		if uval != 0 {
			b |= 0x80
		}
		w.Write([]byte{b})
		if uval == 0 {
			break
		}
	}
}

// writeCompressedUint 写入 LEB128 编码的无符号压缩整数。
func writeCompressedUint(w io.Writer, val uint64) {
	writeCompressedInt(w, int64(val))
}

// writeJFRString 写入 JFR 格式的字符串（编码方式：UTF-8 带长度前缀）。
func writeJFRString(w io.Writer, s string) {
	if s == "" {
		// 空字符串编码: encoding=0 (空字符串)
		w.Write([]byte{0})
		return
	}
	// encoding=3 表示 UTF-8 字符串
	w.Write([]byte{3})
	data := []byte(s)
	writeCompressedInt(w, int64(len(data)))
	w.Write(data)
}

// writeExecutionSampleEvent 写入一个 jdk.ExecutionSample 事件。
func (w *jfrWriter) writeExecutionSampleEvent(buf *bytes.Buffer, sample *jfrExecutionSample) {
	eventBuf := &bytes.Buffer{}

	// 事件类型 ID
	writeCompressedInt(eventBuf, jfrEventTypeExecutionSample)
	// 开始时间 (ticks)
	writeCompressedInt(eventBuf, sample.timestamp)
	// 线程 ID (引用常量池)
	writeCompressedInt(eventBuf, sample.threadID)
	// 栈帧 ID (引用常量池)
	writeCompressedInt(eventBuf, sample.stackTraceID)
	// 线程状态 (引用常量池)
	writeCompressedInt(eventBuf, sample.state)

	// JFR 事件的 size 字段包含 size 字段本身的字节数
	writeEventWithSize(buf, eventBuf.Bytes())
}

// writeCheckpointEvent 写入常量池（checkpoint）事件。
// 注意：writeClassPool 会动态创建 Package，writePackagePool 会动态创建 Symbol，
// 因此必须先将所有常量池数据写入临时 buffer，再计算 poolCount。
func (w *jfrWriter) writeCheckpointEvent(buf *bytes.Buffer) {
	// 第一步：将所有常量池数据写入临时 buffer，同时计数。
	// 写入顺序很重要：Class 必须在 Package 之前（因为 writeClassPool 会创建 Package），
	// Package 必须在 Symbol 之前（因为 writePackagePool 会创建 Symbol）。
	poolsBuf := &bytes.Buffer{}
	poolCount := 0

	if len(w.threads) > 0 {
		w.writeThreadPool(poolsBuf)
		poolCount++
	}
	if len(w.stackTraces) > 0 {
		w.writeStackTracePool(poolsBuf)
		poolCount++
	}
	if len(w.methods) > 0 {
		w.writeMethodPool(poolsBuf)
		poolCount++
	}
	// Class 必须在 Package 之前写入（writeClassPool 会调用 getOrCreatePackage）
	if len(w.classes) > 0 {
		w.writeClassPool(poolsBuf)
		poolCount++
	}
	// Package 必须在 Symbol 之前写入（writePackagePool 会调用 getOrCreateSymbol）
	if len(w.packages) > 0 {
		w.writePackagePool(poolsBuf)
		poolCount++
	}
	// Symbol 在 Package 之后写入，确保包含 writePackagePool 动态创建的 Symbol
	if len(w.symbols) > 0 {
		w.writeSymbolPool(poolsBuf)
		poolCount++
	}
	if len(w.frameTypes) > 0 {
		w.writeFrameTypePool(poolsBuf)
		poolCount++
	}
	// ThreadState 常量池始终有一个 RUNNABLE 状态
	w.writeThreadStatePool(poolsBuf)
	poolCount++

	// 第二步：组装 checkpoint 事件
	cpBuf := &bytes.Buffer{}

	// 事件类型 ID = 1 (checkpoint)
	writeCompressedInt(cpBuf, jfrEventTypeCheckpoint)
	// 开始时间
	writeCompressedInt(cpBuf, w.startTime.UnixNano())
	// Duration
	writeCompressedInt(cpBuf, 0)
	// Delta next (0 = 没有更多 checkpoint)
	writeCompressedInt(cpBuf, 0)
	// Flush (false)
	cpBuf.WriteByte(0)

	// 写入 poolCount（在所有常量池写入之后计算，确保准确）
	writeCompressedInt(cpBuf, int64(poolCount))

	// 写入所有常量池数据
	cpBuf.Write(poolsBuf.Bytes())

	// JFR 事件的 size 字段包含 size 字段本身的字节数
	writeEventWithSize(buf, cpBuf.Bytes())
}

// writeThreadPool 写入线程常量池。
func (w *jfrWriter) writeThreadPool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeThread) // 类型 ID
	writeCompressedInt(buf, int64(len(w.threads))) // 条目数

	for name, id := range w.threads {
		writeCompressedInt(buf, id)       // key (thread ID)
		writeJFRString(buf, name)         // osName
		writeCompressedInt(buf, id)       // osThreadId
		writeJFRString(buf, name)         // javaName
		writeCompressedInt(buf, id)       // javaThreadId
		writeCompressedInt(buf, 0)        // group (null)
	}
}

// writeStackTracePool 写入栈帧常量池。
func (w *jfrWriter) writeStackTracePool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeStackTrace) // 类型 ID
	writeCompressedInt(buf, int64(len(w.stackTraces))) // 条目数

	for _, id := range w.stackTraces {
		writeCompressedInt(buf, id)       // key (stackTrace ID)
		writeCompressedInt(buf, 0)        // truncated (false)

		frames := w.stackTraceFrames[id]
		writeCompressedInt(buf, int64(len(frames))) // frame count
		for _, frame := range frames {
			writeCompressedInt(buf, frame.methodID)
			writeCompressedInt(buf, int64(frame.lineNumber))
			writeCompressedInt(buf, int64(frame.bytecodeIdx))
			writeCompressedInt(buf, frame.frameTypeID)
		}
	}
}

// writeMethodPool 写入方法常量池。
func (w *jfrWriter) writeMethodPool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeMethod) // 类型 ID
	writeCompressedInt(buf, int64(len(w.methods))) // 条目数

	for key, id := range w.methods {
		// 解析 key: "className.methodNamedescriptor"
		className, methodName := parseMethodKey(key)
		classID := w.classes[className]

		writeCompressedInt(buf, id)         // key (method ID)
		writeCompressedInt(buf, classID)    // type (class reference)
		writeJFRString(buf, methodName)     // name (String 类型，直接写字符串)
		writeJFRString(buf, "()V")          // descriptor (String 类型，直接写字符串)
		writeCompressedInt(buf, 0)          // modifiers
		writeCompressedInt(buf, 0)          // hidden (false)
	}
}

// parseMethodKey 解析方法 key "className.methodName()V" 为类名和方法名。
func parseMethodKey(key string) (className, methodName string) {
	// 查找最后一个 '.' 之前的部分作为类名
	// key 格式: "className.methodName()V"
	lastDot := -1
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '.' {
			lastDot = i
			break
		}
	}
	if lastDot < 0 {
		return "[unknown]", key
	}
	className = key[:lastDot]
	rest := key[lastDot+1:]
	// 去掉描述符部分
	for i, c := range rest {
		if c == '(' {
			methodName = rest[:i]
			return
		}
	}
	methodName = rest
	return
}

// writeClassPool 写入类常量池。
func (w *jfrWriter) writeClassPool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeClass) // 类型 ID
	writeCompressedInt(buf, int64(len(w.classes))) // 条目数

	for name, id := range w.classes {
		// 简单处理包名：取最后一个 '/' 之前的部分
		pkgName := ""
		for i := len(name) - 1; i >= 0; i-- {
			if name[i] == '/' || name[i] == '.' {
				pkgName = name[:i]
				break
			}
		}
		pkgID := w.getOrCreatePackage(pkgName)

		writeCompressedInt(buf, id)         // key (class ID)
		writeCompressedInt(buf, 0)          // classLoader (null)
		writeJFRString(buf, name)           // name (String 类型，直接写字符串)
		writeCompressedInt(buf, pkgID)      // package (reference)
		writeCompressedInt(buf, 0)          // modifiers
		writeCompressedInt(buf, 0)          // hidden (false)
	}
}

// writePackagePool 写入包常量池。
func (w *jfrWriter) writePackagePool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypePackage) // 类型 ID
	writeCompressedInt(buf, int64(len(w.packages))) // 条目数

	for name, id := range w.packages {
		nameSymID := w.getOrCreateSymbol(name)
		writeCompressedInt(buf, id)         // key (package ID)
		writeCompressedInt(buf, nameSymID)  // name (symbol reference)
		writeCompressedInt(buf, 0)          // module (null)
		writeCompressedInt(buf, 0)          // exported (false)
	}
}

// writeSymbolPool 写入符号（字符串）常量池。
func (w *jfrWriter) writeSymbolPool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeSymbol) // 类型 ID
	writeCompressedInt(buf, int64(len(w.symbols))) // 条目数

	for s, id := range w.symbols {
		writeCompressedInt(buf, id) // key (symbol ID)
		writeJFRString(buf, s)     // string value
	}
}

// writeFrameTypePool 写入帧类型常量池。
func (w *jfrWriter) writeFrameTypePool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeFrameType) // 类型 ID
	writeCompressedInt(buf, int64(len(w.frameTypes))) // 条目数

	for name, id := range w.frameTypes {
		writeCompressedInt(buf, id)  // key (frameType ID)
		writeJFRString(buf, name)    // description
	}
}

// writeThreadStatePool 写入线程状态常量池。
func (w *jfrWriter) writeThreadStatePool(buf *bytes.Buffer) {
	writeCompressedInt(buf, jfrTypeThreadState) // 类型 ID
	writeCompressedInt(buf, 1)                  // 条目数（只有一个状态：RUNNABLE）

	writeCompressedInt(buf, 0)              // key (state ID = 0)
	writeJFRString(buf, "STATE_RUNNABLE")   // name
}

// writeEventWithSize 写入带有正确 size 前缀的事件数据。
// JFR 事件的 size 字段表示整个事件的总大小（包含 size 字段本身的字节数）。
func writeEventWithSize(buf *bytes.Buffer, eventPayload []byte) {
	payloadLen := len(eventPayload)
	// 计算 size 字段本身占用的 LEB128 字节数
	// size = sizeFieldBytes + payloadLen
	// 需要迭代计算，因为 size 值会影响 size 字段的字节数
	totalSize := payloadLen
	for {
		sizeFieldBytes := compressedIntSize(int64(totalSize))
		newTotal := sizeFieldBytes + payloadLen
		if newTotal == totalSize {
			break
		}
		totalSize = newTotal
	}
	writeCompressedInt(buf, int64(totalSize))
	buf.Write(eventPayload)
}

// compressedIntSize 返回 LEB128 编码一个整数所需的字节数。
func compressedIntSize(val int64) int {
	uval := uint64(val)
	size := 1
	for uval >>= 7; uval != 0; uval >>= 7 {
		size++
	}
	return size
}

// writeMetadataEvent 写入 metadata 事件（描述所有事件类型和字段的结构）。
func (w *jfrWriter) writeMetadataEvent(buf *bytes.Buffer) {
	metaBuf := &bytes.Buffer{}

	// 事件类型 ID = 0 (metadata)
	writeCompressedInt(metaBuf, jfrEventTypeMetadata)
	// 开始时间
	writeCompressedInt(metaBuf, w.startTime.UnixNano())
	// Duration
	writeCompressedInt(metaBuf, 0)
	// Metadata ID
	writeCompressedInt(metaBuf, 0)

	// 写入 metadata 的二进制类描述
	w.writeMetadataDescriptors(metaBuf)

	// JFR 事件的 size 字段包含 size 字段本身的字节数
	writeEventWithSize(buf, metaBuf.Bytes())
}

// writeMetadataDescriptors 写入类型描述元数据。
// JFR metadata 使用一种树形结构来描述所有事件类型。
// 树结构为: root -> [metadata, region]
// metadata 包含所有 class（类型）定义
// region 包含 gmtOffset 和 locale 属性
func (w *jfrWriter) writeMetadataDescriptors(buf *bytes.Buffer) {
	// 构建字符串表（使用 map 来动态添加字符串）
	sp := &jfrStringPool{
		strings: make([]string, 0, 128),
		indices: make(map[string]int),
	}

	// 预注册所有需要的字符串
	// 元素名
	sp.add("root")
	sp.add("metadata")
	sp.add("region")
	sp.add("class")
	sp.add("field")
	sp.add("annotation")
	// 属性名
	sp.add("name")
	sp.add("id")
	sp.add("type") // 保留用于 StackFrame.type 等字段名
	sp.add("superType")
	sp.add("simpleType")
	sp.add("constantPool")
	sp.add("dimension")
	sp.add("gmtOffset")
	sp.add("locale")
	// 属性值
	sp.add("true")
	sp.add("false")
	sp.add("0")
	sp.add("1")
	// 基本类型名
	sp.add("long")
	sp.add("int")
	sp.add("boolean")
	sp.add("float")
	sp.add("double")
	sp.add("short")
	sp.add("char")
	sp.add("byte")
	sp.add("java.lang.String")
	// JFR 事件超类型
	sp.add("jdk.jfr.Event")
	// 事件和类型名
	sp.add("jdk.ExecutionSample")
	sp.add("java.lang.Thread")
	sp.add("jdk.types.StackTrace")
	sp.add("jdk.types.StackFrame")
	sp.add("jdk.types.Method")
	sp.add("java.lang.Class")
	sp.add("jdk.types.Package")
	sp.add("jdk.types.Symbol")
	sp.add("jdk.types.FrameType")
	sp.add("jdk.types.ThreadState")
	sp.add("jdk.types.ClassLoader")
	sp.add("jdk.types.Module")
	sp.add("jdk.types.ThreadGroup")
	// 字段名
	sp.add("startTime")
	sp.add("sampledThread")
	sp.add("stackTrace")
	sp.add("state")
	sp.add("osName")
	sp.add("osThreadId")
	sp.add("javaName")
	sp.add("javaThreadId")
	sp.add("group")
	sp.add("truncated")
	sp.add("frames")
	sp.add("method")
	sp.add("lineNumber")
	sp.add("bytecodeIndex")
	sp.add("descriptor")
	sp.add("modifiers")
	sp.add("hidden")
	sp.add("classLoader")
	sp.add("package")
	sp.add("module")
	sp.add("exported")
	sp.add("string")
	sp.add("description")
	// 类型 ID 的字符串表示（每个类型都需要唯一 ID）
	sp.add(fmt.Sprintf("%d", 2))  // int (如果和 "0","1" 不同)
	sp.add(fmt.Sprintf("%d", 3))  // boolean
	sp.add(fmt.Sprintf("%d", 4))  // java.lang.String
	sp.add(fmt.Sprintf("%d", 5))  // float
	sp.add(fmt.Sprintf("%d", 6))  // double
	sp.add(fmt.Sprintf("%d", 7))  // short
	sp.add(fmt.Sprintf("%d", 8))  // char
	sp.add(fmt.Sprintf("%d", 9))  // byte
	sp.add(fmt.Sprintf("%d", jfrEventTypeExecutionSample))
	sp.add(fmt.Sprintf("%d", jfrTypeThread))
	sp.add(fmt.Sprintf("%d", jfrTypeStackTrace))
	sp.add(fmt.Sprintf("%d", jfrTypeMethod))
	sp.add(fmt.Sprintf("%d", jfrTypeClass))
	sp.add(fmt.Sprintf("%d", jfrTypePackage))
	sp.add(fmt.Sprintf("%d", jfrTypeSymbol))
	sp.add(fmt.Sprintf("%d", jfrTypeFrameType))
	sp.add(fmt.Sprintf("%d", jfrTypeThreadState))
	sp.add(fmt.Sprintf("%d", 210)) // StackFrame
	sp.add(fmt.Sprintf("%d", 211)) // ClassLoader
	sp.add(fmt.Sprintf("%d", 212)) // Module
	sp.add(fmt.Sprintf("%d", 213)) // ThreadGroup
	// locale 值
	sp.add("en_US")

	// 构建元素树
	tree := w.buildMetadataTree(sp)

	// 写入字符串表
	writeCompressedInt(buf, int64(len(sp.strings)))
	for _, s := range sp.strings {
		writeJFRString(buf, s)
	}

	// 写入元素树
	writeMetadataElement(buf, tree)
}

// jfrStringPool 管理 metadata 字符串表。
type jfrStringPool struct {
	strings []string
	indices map[string]int
}

// add 添加字符串到池中（如果不存在），返回索引。
func (p *jfrStringPool) add(s string) int {
	if idx, ok := p.indices[s]; ok {
		return idx
	}
	idx := len(p.strings)
	p.strings = append(p.strings, s)
	p.indices[s] = idx
	return idx
}

// idx 获取字符串的索引。
func (p *jfrStringPool) idx(s string) int {
	if idx, ok := p.indices[s]; ok {
		return idx
	}
	return p.add(s)
}

// metadataElement 表示 metadata 树中的一个元素。
type metadataElement struct {
	nameIdx    int // 字符串表中的索引
	attributes []metadataAttr
	children   []metadataElement
}

// metadataAttr 表示元素的一个属性。
type metadataAttr struct {
	keyIdx   int // 字符串表中的索引
	valueIdx int // 字符串表中的索引
}

// writeMetadataElement 递归写入 metadata 元素。
func writeMetadataElement(buf *bytes.Buffer, elem *metadataElement) {
	writeCompressedInt(buf, int64(elem.nameIdx))

	// 属性数量
	writeCompressedInt(buf, int64(len(elem.attributes)))
	for _, attr := range elem.attributes {
		writeCompressedInt(buf, int64(attr.keyIdx))
		writeCompressedInt(buf, int64(attr.valueIdx))
	}

	// 子元素数量
	writeCompressedInt(buf, int64(len(elem.children)))
	for i := range elem.children {
		writeMetadataElement(buf, &elem.children[i])
	}
}

// buildMetadataTree 构建 metadata 描述树。
// JDK 期望的树结构:
//
//	root
//	  ├── metadata
//	  │   ├── class name="long" id="1" simpleType="true"
//	  │   ├── class name="int" id="2" simpleType="true"
//	  │   ├── class name="jdk.ExecutionSample" id="100" superType="jdk.jfr.Event"
//	  │   │   ├── field name="startTime" type="long"
//	  │   │   ├── field name="sampledThread" type="java.lang.Thread" constantPool="true"
//	  │   │   └── ...
//	  │   └── ...
//	  └── region gmtOffset="0" locale="en_US"
func (w *jfrWriter) buildMetadataTree(sp *jfrStringPool) *metadataElement {
	// 辅助函数：构建字段元素
	// JDK 中 field 的类型引用属性名为 "class"（ATTRIBUTE_TYPE_ID = "class"），
	// 值为类型的数字 ID 字符串（不是类型名）
	typeIDs := map[string]int{
		"long": 1, "int": 2, "boolean": 3, "java.lang.String": 4,
		"float": 5, "double": 6, "short": 7, "char": 8, "byte": 9,
		"jdk.ExecutionSample":    jfrEventTypeExecutionSample,
		"java.lang.Thread":       jfrTypeThread,
		"jdk.types.StackTrace":   jfrTypeStackTrace,
		"jdk.types.StackFrame":   210,
		"jdk.types.Method":       jfrTypeMethod,
		"java.lang.Class":        jfrTypeClass,
		"jdk.types.Package":      jfrTypePackage,
		"jdk.types.Symbol":       jfrTypeSymbol,
		"jdk.types.FrameType":    jfrTypeFrameType,
		"jdk.types.ThreadState":  jfrTypeThreadState,
		"jdk.types.ClassLoader":  211,
		"jdk.types.Module":       212,
		"jdk.types.ThreadGroup":  213,
	}
	makeField := func(name, typeName string, constantPool bool, dimension int) metadataElement {
		typeID := typeIDs[typeName]
		attrs := []metadataAttr{
			{keyIdx: sp.idx("name"), valueIdx: sp.idx(name)},
			{keyIdx: sp.idx("class"), valueIdx: sp.idx(fmt.Sprintf("%d", typeID))},
		}
		if constantPool {
			attrs = append(attrs, metadataAttr{keyIdx: sp.idx("constantPool"), valueIdx: sp.idx("true")})
		}
		dimStr := "0"
		if dimension > 0 {
			dimStr = "1"
		}
		attrs = append(attrs, metadataAttr{keyIdx: sp.idx("dimension"), valueIdx: sp.idx(dimStr)})
		return metadataElement{
			nameIdx:    sp.idx("field"),
			attributes: attrs,
		}
	}

	// 辅助函数：构建类元素
	makeClass := func(name string, id int, superType string, simpleType bool, fields []metadataElement) metadataElement {
		idStr := fmt.Sprintf("%d", id)
		attrs := []metadataAttr{
			{keyIdx: sp.idx("name"), valueIdx: sp.idx(name)},
			{keyIdx: sp.idx("id"), valueIdx: sp.idx(idStr)},
		}
		if superType != "" {
			attrs = append(attrs, metadataAttr{keyIdx: sp.idx("superType"), valueIdx: sp.idx(superType)})
		}
		if simpleType {
			attrs = append(attrs, metadataAttr{keyIdx: sp.idx("simpleType"), valueIdx: sp.idx("true")})
		}
		return metadataElement{
			nameIdx:    sp.idx("class"),
			attributes: attrs,
			children:   fields,
		}
	}

	// 构建所有类型描述
	// 注意：基本类型不能标记 simpleType=true，因为 JDK 的 ValueDescriptor.getTypeName()
	// 对 simpleType 类型会调用 type.getFields().get(0)，要求至少有一个字段。
	// 没有字段的基本类型应该让 JDK 的 calculateSimpleType() 自动计算（会返回 false）。
	classes := []metadataElement{
		// 基本类型（simpleType=false，因为没有字段）
		makeClass("long", 1, "", false, nil),
		makeClass("int", 2, "", false, nil),
		makeClass("boolean", 3, "", false, nil),
		makeClass("java.lang.String", 4, "", false, nil),
		makeClass("float", 5, "", false, nil),
		makeClass("double", 6, "", false, nil),
		makeClass("short", 7, "", false, nil),
		makeClass("char", 8, "", false, nil),
		makeClass("byte", 9, "", false, nil),

		// jdk.ExecutionSample 事件（superType="jdk.jfr.Event" 标识为事件类型）
		makeClass("jdk.ExecutionSample", jfrEventTypeExecutionSample, "jdk.jfr.Event", false, []metadataElement{
			makeField("startTime", "long", false, 0),
			makeField("sampledThread", "java.lang.Thread", true, 0),
			makeField("stackTrace", "jdk.types.StackTrace", true, 0),
			makeField("state", "jdk.types.ThreadState", true, 0),
		}),

		// java.lang.Thread
		makeClass("java.lang.Thread", jfrTypeThread, "", false, []metadataElement{
			makeField("osName", "java.lang.String", false, 0),
			makeField("osThreadId", "long", false, 0),
			makeField("javaName", "java.lang.String", false, 0),
			makeField("javaThreadId", "long", false, 0),
			makeField("group", "jdk.types.ThreadGroup", true, 0),
		}),

		// jdk.types.StackTrace
		makeClass("jdk.types.StackTrace", jfrTypeStackTrace, "", false, []metadataElement{
			makeField("truncated", "boolean", false, 0),
			makeField("frames", "jdk.types.StackFrame", false, 1),
		}),

		// jdk.types.StackFrame
		makeClass("jdk.types.StackFrame", 210, "", false, []metadataElement{
			makeField("method", "jdk.types.Method", true, 0),
			makeField("lineNumber", "int", false, 0),
			makeField("bytecodeIndex", "int", false, 0),
			makeField("type", "jdk.types.FrameType", true, 0),
		}),

		// jdk.types.Method
		makeClass("jdk.types.Method", jfrTypeMethod, "", false, []metadataElement{
			makeField("type", "java.lang.Class", true, 0),
			makeField("name", "java.lang.String", false, 0),
			makeField("descriptor", "java.lang.String", false, 0),
			makeField("modifiers", "int", false, 0),
			makeField("hidden", "boolean", false, 0),
		}),

		// java.lang.Class
		makeClass("java.lang.Class", jfrTypeClass, "", false, []metadataElement{
			makeField("classLoader", "jdk.types.ClassLoader", true, 0),
			makeField("name", "java.lang.String", false, 0),
			makeField("package", "jdk.types.Package", true, 0),
			makeField("modifiers", "int", false, 0),
			makeField("hidden", "boolean", false, 0),
		}),

		// jdk.types.Package
		makeClass("jdk.types.Package", jfrTypePackage, "", false, []metadataElement{
			makeField("name", "jdk.types.Symbol", true, 0),
			makeField("module", "jdk.types.Module", true, 0),
			makeField("exported", "boolean", false, 0),
		}),

		// jdk.types.Symbol
		makeClass("jdk.types.Symbol", jfrTypeSymbol, "", false, []metadataElement{
			makeField("string", "java.lang.String", false, 0),
		}),

		// jdk.types.FrameType
		makeClass("jdk.types.FrameType", jfrTypeFrameType, "", false, []metadataElement{
			makeField("description", "java.lang.String", false, 0),
		}),

		// jdk.types.ThreadState
		makeClass("jdk.types.ThreadState", jfrTypeThreadState, "", false, []metadataElement{
			makeField("name", "java.lang.String", false, 0),
		}),

		// jdk.types.ClassLoader（空类型，仅用于引用）
		makeClass("jdk.types.ClassLoader", 211, "", false, nil),

		// jdk.types.Module（空类型，仅用于引用）
		makeClass("jdk.types.Module", 212, "", false, nil),

		// jdk.types.ThreadGroup（空类型，仅用于引用）
		makeClass("jdk.types.ThreadGroup", 213, "", false, nil),
	}

	// 构建正确的三层树结构: root -> [metadata, region]
	return &metadataElement{
		nameIdx:    sp.idx("root"),
		attributes: nil,
		children: []metadataElement{
			{
				// metadata 元素包含所有类型定义
				nameIdx:    sp.idx("metadata"),
				attributes: nil,
				children:   classes,
			},
			{
				// region 元素包含时区和语言信息
				nameIdx: sp.idx("region"),
				attributes: []metadataAttr{
					{keyIdx: sp.idx("gmtOffset"), valueIdx: sp.idx("0")},
					{keyIdx: sp.idx("locale"), valueIdx: sp.idx("en_US")},
				},
				children: nil,
			},
		},
	}
}
