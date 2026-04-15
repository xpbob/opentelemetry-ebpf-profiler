// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// usdtProbeInfo 保存从 .note.stapsdt section 解析出的 USDT 探针信息。
type usdtProbeInfo struct {
	// Provider 是 USDT 探针的 provider 名称（如 "parcagpu"）。
	Provider string
	// Name 是 USDT 探针的名称（如 "cuda_correlation"）。
	Name string
	// LocationVA 是探针在 ELF 中的虚拟地址（Location）。
	LocationVA uint64
	// BaseVA 是探针的 base 地址（用于 PC-relative 寻址）。
	BaseVA uint64
	// SemaphoreVA 是探针信号量的虚拟地址，0 表示无信号量。
	SemaphoreVA uint64
	// Arguments 是探针参数描述字符串。
	Arguments string
	// FileOffset 是 LocationVA 转换后的文件偏移量，可直接用于 uprobe 挂载。
	FileOffset uint64
	// SemaphoreFileOffset 是 SemaphoreVA 转换后的文件偏移量。
	SemaphoreFileOffset uint64
}

// NT_STAPSDT 是 SystemTap USDT 探针的 ELF note 类型。
const ntStapSDT elf.NType = 3

// parseUSDTNotes 从指定的 ELF 文件中解析 .note.stapsdt section，
// 返回所有 USDT 探针信息。
func parseUSDTNotes(elfPath string) ([]usdtProbeInfo, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file %q: %w", elfPath, err)
	}
	defer f.Close()

	// 查找 .note.stapsdt section
	sec := f.Section(".note.stapsdt")
	if sec == nil {
		return nil, fmt.Errorf("ELF file %q does not contain .note.stapsdt section", elfPath)
	}

	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .note.stapsdt section: %w", err)
	}

	// 确定 ELF 位数（地址大小）
	var addrSize int
	switch f.Class {
	case elf.ELFCLASS64:
		addrSize = 8
	case elf.ELFCLASS32:
		addrSize = 4
	default:
		return nil, fmt.Errorf("unsupported ELF class: %v", f.Class)
	}

	var probes []usdtProbeInfo
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		// 解析 ELF note header: namesz, descsz, type (各 4 字节)
		var namesz, descsz uint32
		var noteType uint32
		if err := binary.Read(reader, f.ByteOrder, &namesz); err != nil {
			break
		}
		if err := binary.Read(reader, f.ByteOrder, &descsz); err != nil {
			break
		}
		if err := binary.Read(reader, f.ByteOrder, &noteType); err != nil {
			break
		}

		// 读取 name（4 字节对齐）
		nameAligned := align4(namesz)
		nameBytes := make([]byte, nameAligned)
		if _, err := reader.Read(nameBytes); err != nil {
			break
		}
		// 去掉 null 终止符
		name := string(bytes.TrimRight(nameBytes[:namesz], "\x00"))

		// 读取 desc（4 字节对齐）
		descAligned := align4(descsz)
		descBytes := make([]byte, descAligned)
		if _, err := reader.Read(descBytes); err != nil {
			break
		}

		// 只处理 stapsdt note
		if name != "stapsdt" || elf.NType(noteType) != ntStapSDT {
			continue
		}

		// 解析 desc 内容：
		// - Location (地址大小)
		// - Base (地址大小)
		// - Semaphore (地址大小)
		// - Provider\0Name\0Arguments\0
		descReader := bytes.NewReader(descBytes[:descsz])

		var location, base, semaphore uint64
		if addrSize == 8 {
			if err := binary.Read(descReader, f.ByteOrder, &location); err != nil {
				continue
			}
			if err := binary.Read(descReader, f.ByteOrder, &base); err != nil {
				continue
			}
			if err := binary.Read(descReader, f.ByteOrder, &semaphore); err != nil {
				continue
			}
		} else {
			var loc32, base32, sem32 uint32
			if err := binary.Read(descReader, f.ByteOrder, &loc32); err != nil {
				continue
			}
			if err := binary.Read(descReader, f.ByteOrder, &base32); err != nil {
				continue
			}
			if err := binary.Read(descReader, f.ByteOrder, &sem32); err != nil {
				continue
			}
			location = uint64(loc32)
			base = uint64(base32)
			semaphore = uint64(sem32)
		}

		// 剩余部分是三个 null 终止的字符串：provider, name, arguments
		remaining := make([]byte, descReader.Len())
		if _, err := descReader.Read(remaining); err != nil {
			continue
		}

		strings := bytes.SplitN(remaining, []byte{0}, 4)
		if len(strings) < 3 {
			continue
		}

		probe := usdtProbeInfo{
			Provider:    string(strings[0]),
			Name:        string(strings[1]),
			Arguments:   string(strings[2]),
			LocationVA:  location,
			BaseVA:      base,
			SemaphoreVA: semaphore,
		}

		// 将虚拟地址转换为文件偏移
		probe.FileOffset = vaToFileOffset(f, location)
		if semaphore != 0 {
			probe.SemaphoreFileOffset = vaToFileOffset(f, semaphore)
		}

		probes = append(probes, probe)
	}

	if len(probes) == 0 {
		return nil, fmt.Errorf("no USDT probes found in %q", elfPath)
	}

	return probes, nil
}

// findUSDTProbe 在 ELF 文件中查找指定 provider:name 的 USDT 探针。
func findUSDTProbe(elfPath, provider, probeName string) (*usdtProbeInfo, error) {
	probes, err := parseUSDTNotes(elfPath)
	if err != nil {
		return nil, err
	}

	for i := range probes {
		if probes[i].Provider == provider && probes[i].Name == probeName {
			return &probes[i], nil
		}
	}

	return nil, fmt.Errorf("USDT probe %s:%s not found in %q (found %d probes)",
		provider, probeName, elfPath, len(probes))
}

// vaToFileOffset 将 ELF 虚拟地址转换为文件偏移。
// 遍历 PT_LOAD 段，找到包含该 VA 的段，然后计算文件偏移。
func vaToFileOffset(f *elf.File, va uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if va >= prog.Vaddr && va < prog.Vaddr+prog.Memsz {
			return va - prog.Vaddr + prog.Off
		}
	}
	// 如果找不到对应的 PT_LOAD 段，直接返回 VA（可能是 ET_EXEC 类型）
	return va
}

// align4 将值向上对齐到 4 字节边界。
func align4(v uint32) uint32 {
	return (v + 3) &^ 3
}

// usdtArgSpec 描述如何从 pt_regs 中读取一个 USDT 参数。
// 与 eBPF 侧的 UsdtArgSpec 结构体布局一致。
type usdtArgSpec struct {
	RegOffset  int16  // 寄存器在 pt_regs 中的字节偏移，-1 表示无效
	MemOffset  int16  // 内存偏移（间接寻址时使用）
	Size       uint8  // 参数大小（字节）：1, 2, 4, 8
	IsIndirect uint8  // 是否间接寻址
	IsSigned   uint8  // 是否有符号
	Pad        uint8  // 对齐填充
}

// usdtArgsConfig 描述一个 USDT 探针的所有参数如何读取。
// 与 eBPF 侧的 UsdtArgsConfig 结构体布局一致。
type usdtArgsConfig struct {
	NumArgs uint8        // 有效参数个数
	Pad     [7]uint8     // 对齐填充
	Args    [8]usdtArgSpec // 各参数的读取描述
}

// x86_64RegToPtregsOffset 将 x86_64 寄存器名映射到 pt_regs 结构体中的字节偏移。
// pt_regs 布局（参见 kernel.h）：
//
//	r15(0) r14(8) r13(16) r12(24) bp(32) bx(40)
//	r11(48) r10(56) r9(64) r8(72)
//	ax(80) cx(88) dx(96) si(104) di(112)
//	orig_ax(120) ip(128) cs(136) flags(144) sp(152) ss(160)
var x86_64RegToPtregsOffset = map[string]int16{
	// 64 位寄存器
	"rax": 80, "rbx": 40, "rcx": 88, "rdx": 96,
	"rsi": 104, "rdi": 112, "rbp": 32, "rsp": 152,
	"r8": 72, "r9": 64, "r10": 56, "r11": 48,
	"r12": 24, "r13": 16, "r14": 8, "r15": 0,
	"rip": 128,
	// 32 位寄存器（低 32 位，使用相同偏移）
	"eax": 80, "ebx": 40, "ecx": 88, "edx": 96,
	"esi": 104, "edi": 112, "ebp": 32, "esp": 152,
	"r8d": 72, "r9d": 64, "r10d": 56, "r11d": 48,
	"r12d": 24, "r13d": 16, "r14d": 8, "r15d": 0,
	// 16 位寄存器
	"ax": 80, "bx": 40, "cx": 88, "dx": 96,
	"si": 104, "di": 112, "bp": 32, "sp": 152,
	"r8w": 72, "r9w": 64, "r10w": 56, "r11w": 48,
	"r12w": 24, "r13w": 16, "r14w": 8, "r15w": 0,
	// 8 位寄存器
	"al": 80, "bl": 40, "cl": 88, "dl": 96,
	"sil": 104, "dil": 112, "bpl": 32, "spl": 152,
	"r8b": 72, "r9b": 64, "r10b": 56, "r11b": 48,
	"r12b": 24, "r13b": 16, "r14b": 8, "r15b": 0,
}

// parseSDTArg 解析单个 SDT 参数描述字符串。
// 格式为 "[-]size@location"，其中 location 可以是：
//   - %reg          — 寄存器直接读取
//   - offset(%reg)  — 寄存器间接读取（基址 + 偏移）
//   - $literal      — 立即数（不支持，返回无效）
//
// 示例：
//
//	"4@%r12d"       -> 从 r12 寄存器读取 4 字节
//	"-4@%r14d"      -> 从 r14 寄存器读取有符号 4 字节
//	"8@%r13"        -> 从 r13 寄存器读取 8 字节
//	"8@16(%r14)"    -> 从 *(r14 + 16) 读取 8 字节
//	"4@92(%r14)"    -> 从 *(r14 + 92) 读取 4 字节
func parseSDTArg(arg string) (usdtArgSpec, error) {
	spec := usdtArgSpec{RegOffset: -1}

	// 解析 "[-]size@location"
	atIdx := -1
	for i, c := range arg {
		if c == '@' {
			atIdx = i
			break
		}
	}
	if atIdx < 0 {
		return spec, fmt.Errorf("invalid SDT arg format (no '@'): %q", arg)
	}

	sizeStr := arg[:atIdx]
	location := arg[atIdx+1:]

	// 解析 size（可能带负号表示有符号）
	isSigned := false
	if len(sizeStr) > 0 && sizeStr[0] == '-' {
		isSigned = true
		sizeStr = sizeStr[1:]
	}

	var size int
	if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
		return spec, fmt.Errorf("invalid SDT arg size %q: %v", sizeStr, err)
	}
	if size != 1 && size != 2 && size != 4 && size != 8 {
		return spec, fmt.Errorf("unsupported SDT arg size: %d", size)
	}
	spec.Size = uint8(size)
	if isSigned {
		spec.IsSigned = 1
	}

	// 解析 location
	if len(location) == 0 {
		return spec, fmt.Errorf("empty SDT arg location")
	}

	// 立即数：$literal
	if location[0] == '$' {
		// 立即数不支持，返回无效
		return spec, fmt.Errorf("immediate value SDT args not supported: %q", arg)
	}

	// 寄存器直接读取：%reg
	if location[0] == '%' {
		regName := location[1:]
		offset, ok := x86_64RegToPtregsOffset[regName]
		if !ok {
			return spec, fmt.Errorf("unknown x86_64 register: %q", regName)
		}
		spec.RegOffset = offset
		spec.IsIndirect = 0
		return spec, nil
	}

	// 寄存器间接读取：offset(%reg)
	// 格式：数字(%寄存器名)
	parenIdx := -1
	for i, c := range location {
		if c == '(' {
			parenIdx = i
			break
		}
	}
	if parenIdx < 0 || location[len(location)-1] != ')' {
		return spec, fmt.Errorf("invalid SDT arg location format: %q", location)
	}

	offsetStr := location[:parenIdx]
	regStr := location[parenIdx+1 : len(location)-1]

	// 解析偏移量
	var memOffset int
	if offsetStr == "" {
		memOffset = 0
	} else {
		if _, err := fmt.Sscanf(offsetStr, "%d", &memOffset); err != nil {
			return spec, fmt.Errorf("invalid SDT arg memory offset %q: %v", offsetStr, err)
		}
	}

	// 解析寄存器
	if len(regStr) < 2 || regStr[0] != '%' {
		return spec, fmt.Errorf("invalid SDT arg register format: %q", regStr)
	}
	regName := regStr[1:]
	offset, ok := x86_64RegToPtregsOffset[regName]
	if !ok {
		return spec, fmt.Errorf("unknown x86_64 register: %q", regName)
	}

	spec.RegOffset = offset
	spec.MemOffset = int16(memOffset)
	spec.IsIndirect = 1
	return spec, nil
}

// parseSDTArguments 解析 SDT Arguments 字符串，返回 usdtArgsConfig。
// Arguments 字符串是空格分隔的参数描述列表，如：
//
//	"4@%r12d -4@%r14d 8@%r13"
//	"8@16(%r14) 8@24(%r14) 4@92(%r14) 4@40(%r14) 4@48(%r14) 4@%eax 8@144(%r14) 8@104(%r14)"
func parseSDTArguments(arguments string) (usdtArgsConfig, error) {
	config := usdtArgsConfig{}

	if arguments == "" {
		return config, nil
	}

	// 按空格分割参数
	args := splitFields(arguments)
	if len(args) > 8 {
		return config, fmt.Errorf("too many SDT arguments (%d > 8): %q", len(args), arguments)
	}

	for i, arg := range args {
		spec, err := parseSDTArg(arg)
		if err != nil {
			return config, fmt.Errorf("failed to parse SDT arg %d (%q): %v", i, arg, err)
		}
		config.Args[i] = spec
	}
	config.NumArgs = uint8(len(args))

	return config, nil
}

// splitFields 按空格分割字符串，忽略连续空格。
func splitFields(s string) []string {
	var fields []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields
}
