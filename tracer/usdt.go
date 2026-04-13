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
