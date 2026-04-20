// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// elfFuncSymbol 表示一个 ELF 函数符号，用于按地址查找。
type elfFuncSymbol struct {
	Name string
	Addr uint64
	Size uint64
}

// elfSymbolTable 保存一个 ELF 文件中所有函数符号，按地址排序以支持二分查找。
type elfSymbolTable struct {
	symbols []elfFuncSymbol
}

// lookupByAddress 通过地址查找函数名。
// addr 是 ELF 虚拟地址空间中的地址。
// 返回函数名和函数内偏移，如果未找到返回空字符串。
func (st *elfSymbolTable) lookupByAddress(addr uint64) (string, uint64) {
	if len(st.symbols) == 0 {
		return "", 0
	}

	// 二分查找：找到最后一个 Addr <= addr 的符号
	idx := sort.Search(len(st.symbols), func(i int) bool {
		return st.symbols[i].Addr > addr
	}) - 1

	if idx < 0 {
		return "", 0
	}

	sym := &st.symbols[idx]
	// 如果符号有 size 信息，检查地址是否在范围内
	if sym.Size > 0 && addr >= sym.Addr+sym.Size {
		return "", 0
	}
	// 如果符号没有 size 信息（size == 0），仍然返回最近的符号
	return sym.Name, addr - sym.Addr
}

// elfSymbolResolver 提供基于 ELF 符号表的本地符号化能力。
// 它缓存已解析的 ELF 符号表，避免重复打开和解析同一个文件。
// 通过解析 /proc/<pid>/maps 获取精确的文件路径映射。
type elfSymbolResolver struct {
	mu       sync.Mutex
	cache    map[string]*elfSymbolTable // key: 基础文件名（如 "bobadd"）
	pid      int64                      // 目标进程 PID
	pathMap  map[string]string          // 基础文件名 → 完整路径（从 /proc/pid/maps 解析）
	pathInit bool                       // pathMap 是否已初始化
}

// newElfSymbolResolver 创建一个新的 ELF 符号解析器。
func newElfSymbolResolver(pid int64) *elfSymbolResolver {
	return &elfSymbolResolver{
		cache:   make(map[string]*elfSymbolTable),
		pid:     pid,
		pathMap: make(map[string]string),
	}
}

// resolve 尝试通过 ELF 符号表将地址解析为函数名。
// fileName 是 ELF 文件的基础名称（如 "bobadd" 或 "libc.so.6"）。
// addr 是 ELF 虚拟地址空间中的地址。
// 返回函数名，如果无法解析返回空字符串。
func (r *elfSymbolResolver) resolve(fileName string, addr uint64) string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// 检查缓存
	if st, ok := r.cache[fileName]; ok {
		if st == nil {
			return "" // 之前加载失败
		}
		name, _ := st.lookupByAddress(addr)
		return name
	}

	// 懒加载 /proc/<pid>/maps 路径映射
	if !r.pathInit {
		r.loadPathMap()
		r.pathInit = true
	}

	// 查找文件的完整路径并加载符号表
	st := r.loadSymbolTableForFile(fileName)
	r.cache[fileName] = st
	if st != nil {
		name, _ := st.lookupByAddress(addr)
		return name
	}

	return ""
}

// loadPathMap 解析 /proc/<pid>/maps，建立基础文件名到完整路径的映射。
func (r *elfSymbolResolver) loadPathMap() {
	if r.pid <= 0 {
		return
	}

	mapsPath := fmt.Sprintf("%s/%d/maps", process.ProcFSRoot, r.pid)
	f, err := os.Open(mapsPath)
	if err != nil {
		log.Debugf("Failed to open %s for symbol resolution: %v", mapsPath, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// /proc/pid/maps 格式: addr-addr perms offset dev inode pathname
		// 例如: 55fe8273c000-55fe827be000 r-xp 0002c000 fd:01 1068432 /usr/bin/bobadd
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		filePath := fields[5]
		if filePath == "" || filePath[0] != '/' {
			continue
		}
		baseName := path.Base(filePath)
		// 只记录第一次出现的路径（通常是正确的）
		if _, exists := r.pathMap[baseName]; !exists {
			r.pathMap[baseName] = filePath
		}
	}
}

// loadSymbolTableForFile 根据基础文件名查找并加载符号表。
func (r *elfSymbolResolver) loadSymbolTableForFile(fileName string) *elfSymbolTable {
	// 优先从 /proc/<pid>/maps 获取的路径加载
	if filePath, ok := r.pathMap[fileName]; ok {
		// 通过 /proc/<pid>/root/ 前缀访问，确保在正确的 mount namespace 中
		if r.pid > 0 {
			procRootPath := fmt.Sprintf("%s/%d/root%s", process.ProcFSRoot, r.pid, filePath)
			if st := r.loadSymbolTable(procRootPath); st != nil {
				return st
			}
		}
		// 直接尝试原始路径
		if st := r.loadSymbolTable(filePath); st != nil {
			return st
		}
	}

	return nil
}

// loadSymbolTable 从 ELF 文件中加载函数符号表。
func (r *elfSymbolResolver) loadSymbolTable(filePath string) *elfSymbolTable {
	ef, err := elf.Open(filePath)
	if err != nil {
		return nil
	}
	defer ef.Close()

	var allSyms []elf.Symbol

	// 优先从 .symtab 读取（包含更完整的符号信息）
	if syms, err := ef.Symbols(); err == nil {
		allSyms = append(allSyms, syms...)
	}

	// 如果 .symtab 为空，尝试 .dynsym
	if len(allSyms) == 0 {
		if dynsyms, err := ef.DynamicSymbols(); err == nil {
			allSyms = append(allSyms, dynsyms...)
		}
	}

	if len(allSyms) == 0 {
		return nil
	}

	// 过滤出函数符号并排序
	funcSyms := make([]elfFuncSymbol, 0, len(allSyms)/2)
	for _, sym := range allSyms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Value != 0 {
			funcSyms = append(funcSyms, elfFuncSymbol{
				Name: sym.Name,
				Addr: sym.Value,
				Size: sym.Size,
			})
		}
	}

	if len(funcSyms) == 0 {
		return nil
	}

	sort.Slice(funcSyms, func(i, j int) bool {
		return funcSyms[i].Addr < funcSyms[j].Addr
	})

	log.Debugf("Loaded %d function symbols from %s", len(funcSyms), filePath)

	return &elfSymbolTable{symbols: funcSyms}
}
