// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
)

// ErrNoMappings is returned when no mappings can be extracted.
var ErrNoMappings = errors.New("no mappings")

// ErrCallbackStopped is returned when the IterateMappings callback returns
// false, signaling that iteration was intentionally interrupted.
var ErrCallbackStopped = errors.New("IterateMappings stopped by callback")

// ProcFSRoot 是 procfs 的挂载路径。
// 物理机上运行时为默认值 "/proc"；
// 容器内运行时，需要将宿主机的 /proc 挂载到容器内（如 -v /proc:/host/proc:ro），
// 然后通过 -host-proc=/host/proc 参数设置此变量。
// 这样 profiler 就能通过宿主机的 /proc 访问所有进程的信息，
// 解决容器内 PID namespace 隔离导致的进程不可见问题。
var ProcFSRoot = "/proc"

// ProcPath 构建 procfs 下的路径。
// 例如 ProcPath(1234, "maps") 返回 "/proc/1234/maps"（物理机）
// 或 "/host/proc/1234/maps"（容器内，ProcFSRoot="/host/proc"）。
func ProcPath(pid libpf.PID, subpath string) string {
	return fmt.Sprintf("%s/%d/%s", ProcFSRoot, pid, subpath)
}

// ProcPathStr 与 ProcPath 类似，但 pid 参数为 int 类型。
func ProcPathStr(pid int, subpath string) string {
	return fmt.Sprintf("%s/%d/%s", ProcFSRoot, pid, subpath)
}

// ProcSelfPath 构建 /proc/self 下的路径。
func ProcSelfPath(subpath string) string {
	return fmt.Sprintf("%s/self/%s", ProcFSRoot, subpath)
}

// ResolveHostPID 将用户传入的 PID 转换为宿主机 PID。
// 在容器中运行时，用户传入的 PID 可能是容器内的 namespace PID，
// 而 eBPF 程序（bpf_get_current_pid_tgid）返回的是宿主机全局 PID。
//
// 解析策略：
// 1. 当 ProcFSRoot != "/proc"（容器模式，挂载了宿主机 /proc）时：
//    遍历宿主机 /proc 下所有进程，读取每个进程的 NStgid 字段，
//    找到 NStgid 中包含用户传入的 namespace PID 的那个进程的宿主机 PID。
// 2. 当 ProcFSRoot == "/proc"（物理机模式）时：
//    直接读取 /proc/<pid>/status 中的 NStgid 字段获取宿主机 PID，
//    或通过 /proc/<pid>/sched 获取宿主机 PID。
func ResolveHostPID(pid int) int {
	if pid <= 0 {
		return pid
	}

	// 容器模式：ProcFSRoot 指向宿主机的 /proc（如 /host/proc）
	if ProcFSRoot != "/proc" {
		hostPID := findHostPIDByNamespacePID(pid)
		if hostPID > 0 {
			log.Infof("容器模式 PID 映射：namespace PID %d -> 宿主机 PID %d", pid, hostPID)
			return hostPID
		}
		log.Warnf("容器模式下未找到 namespace PID %d 对应的宿主机 PID，"+
			"将直接使用 PID %d（如果这是宿主机 PID 则正常工作）", pid, pid)
		return pid
	}

	// 物理机模式：ProcFSRoot == "/proc"
	statusPath := ProcPathStr(pid, "status")
	if data, err := os.ReadFile(statusPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "NStgid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					hostPID, err := strconv.Atoi(fields[1])
					if err == nil && hostPID != pid {
						log.Infof("PID namespace 检测（NStgid）：容器内 PID %d -> 宿主机 PID %d", pid, hostPID)
						return hostPID
					}
				}
				break
			}
		}
	}

	schedPath := ProcPathStr(pid, "sched")
	if data, err := os.ReadFile(schedPath); err == nil {
		firstLine := strings.SplitN(string(data), "\n", 2)[0]
		if start := strings.Index(firstLine, "("); start >= 0 {
			if end := strings.Index(firstLine[start:], ","); end >= 0 {
				pidStr := strings.TrimSpace(firstLine[start+1 : start+end])
				if hostPID, err := strconv.Atoi(pidStr); err == nil && hostPID != pid {
					log.Infof("PID namespace 检测（sched）：容器内 PID %d -> 宿主机 PID %d", pid, hostPID)
					return hostPID
				}
			}
		}
	}

	return pid
}

// findHostPIDByNamespacePID 遍历宿主机 /proc 下所有进程，
// 找到 NStgid 中包含指定 namespace PID 的进程，返回其宿主机 PID。
func findHostPIDByNamespacePID(nsPID int) int {
	entries, err := os.ReadDir(ProcFSRoot)
	if err != nil {
		log.Warnf("无法读取 %s 目录: %v", ProcFSRoot, err)
		return 0
	}

	nsPIDStr := strconv.Itoa(nsPID)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hostPID, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		statusPath := fmt.Sprintf("%s/%s/status", ProcFSRoot, entry.Name())
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "NStgid:") {
				continue
			}
			fields := strings.Fields(line)
			// NStgid 格式: "NStgid:\t<host_pid>\t[<ns_pid>...]"
			// fields[0] = "NStgid:", fields[1] = host_pid, fields[2..] = namespace PIDs
			//
			// 情况 1: len(fields) >= 3 — 进程在嵌套 PID namespace 中，
			//         最后一个字段是最内层 namespace PID。
			// 情况 2: len(fields) == 2 — 进程不在嵌套 PID namespace 中
			//         （如 --pid=host 模式），只有一个 PID 值。
			if len(fields) >= 3 {
				innermostNsPID := fields[len(fields)-1]
				if innermostNsPID == nsPIDStr && hostPID != nsPID {
					return hostPID
				}
			} else if len(fields) == 2 {
				// --pid=host 模式或无嵌套 namespace：NStgid 只有一个值，
				// 此时 hostPID 就是实际 PID，如果与 nsPID 匹配则直接返回。
				if fields[1] == nsPIDStr {
					log.Infof("进程 PID %d 不在嵌套 PID namespace 中（可能是 --pid=host 模式），无需转换", nsPID)
					return hostPID
				}
			}
			break
		}
	}

	return 0
}

const (
	containerSource = "[0-9a-f]{64}"
	taskSource      = "[0-9a-f]{32}-\\d+"
)

//nolint:lll
var (
	// expLine matches a line in the /proc/<pid>/cgroup file. It has a submatch for the last element (path), which contains the container ID. Supports both cgroup v1 and v2.
	expLine = regexp.MustCompile(`^\d+:[^:]*:(.+)$`)

	// Inspired from https://github.com/DataDog/dd-otel-host-profiler/blob/1e50a36d4c3a8a87f0cc828f37b48455ec436e55/containermetadata/container.go#L32-L47 with the following changes to handle unit tests in process_test.go:
	// - support prefix after `scope` to handle "0::/system.slice/docker-b1eba9dfaeba29d8b80532a574a03ea3cac29384327f339c26da13649e2120df.scope/init"
	// - remove uuidSource to doesn't match "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-868f9513-eee8-457d-8e36-1b37ae8ae622.scope"
	expContainerID = regexp.MustCompile(fmt.Sprintf(`(%s|%s)(?:\.scope)?(?:/[a-z]+)?$`, containerSource, taskSource))
)

// systemProcess provides an implementation of the Process interface for a
// process that is currently running on this machine.
type systemProcess struct {
	pid libpf.PID
	tid libpf.PID

	mainThreadExit bool
	remoteMemory   remotememory.RemoteMemory

	fileToMapping map[string]*RawMapping
}

var _ Process = &systemProcess{}

var bufPool sync.Pool

// mappingParseBufferSize defines the initial buffer size used to store lines from
// /proc/PID/maps during parsing of mappings.

const mappingParseBufferSize = 256

func init() {
	bufPool = sync.Pool{
		New: func() any {
			buf := make([]byte, mappingParseBufferSize)
			return &buf
		},
	}
}

// New returns an object with Process interface accessing it
func New(pid, tid libpf.PID) Process {
	return &systemProcess{
		pid:          pid,
		tid:          tid,
		remoteMemory: remotememory.NewProcessVirtualMemory(pid),
	}
}

func (sp *systemProcess) PID() libpf.PID {
	return sp.pid
}

func (sp *systemProcess) GetMachineData() MachineData {
	return MachineData{Machine: pfelf.CurrentMachine}
}

func (sp *systemProcess) GetExe() (libpf.String, error) {
	str, err := os.Readlink(ProcPath(sp.pid, "exe"))
	if err != nil {
		return libpf.NullString, err
	}
	return libpf.Intern(str), nil
}

func (sp *systemProcess) GetProcessMeta(cfg MetaConfig) ProcessMeta {
	var processName libpf.String
	exePath, _ := sp.GetExe()
	if name, err := os.ReadFile(ProcPath(sp.pid, "comm")); err == nil {
		processName = libpf.Intern(pfunsafe.ToString(name))
	}

	var envVarMap map[libpf.String]libpf.String
	if len(cfg.IncludeEnvVars) > 0 {
		if envVars, err := os.ReadFile(ProcPath(sp.pid, "environ")); err == nil {
			envVarMap = make(map[libpf.String]libpf.String, len(cfg.IncludeEnvVars))
			// environ has environment variables separated by a null byte (hex: 00)
			for envVar := range strings.SplitSeq(pfunsafe.ToString(envVars), "\000") {
				var fields [2]string
				if stringutil.SplitN(envVar, "=", fields[:]) < 2 {
					continue
				}
				if _, ok := cfg.IncludeEnvVars[fields[0]]; ok {
					envVarMap[libpf.Intern(fields[0])] = libpf.Intern(fields[1])
				}
			}
		}
	}

	containerID, err := extractContainerID(sp.pid)
	if err != nil {
		log.Debugf("Failed extracting containerID for %d: %v", sp.pid, err)
	}
	return ProcessMeta{
		Name:         processName,
		Executable:   exePath,
		ContainerID:  containerID,
		EnvVariables: envVarMap,
	}
}

// parseContainerID parses cgroup v1 and v2 container IDs
func parseContainerID(cgroupFile io.Reader) libpf.String {
	scanner := bufio.NewScanner(cgroupFile)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	for scanner.Scan() {
		b := scanner.Bytes()
		if bytes.Equal(b, []byte("0::/")) {
			continue // Skip a common case
		}
		line := pfunsafe.ToString(b)
		m := expLine.FindStringSubmatchIndex(line)
		if len(m) == 4 {
			sub := line[m[2]:m[3]]
			if parts := expContainerID.FindStringSubmatchIndex(sub); len(parts) == 4 {
				return libpf.Intern(sub[parts[2]:parts[3]])
			}
		}
		log.Debugf("Could not extract container ID from line: %s", line)
	}

	// No containerID could be extracted
	return libpf.NullString
}

// extractContainerID returns the containerID for pid (supports both cgroup v1 and v2)
func extractContainerID(pid libpf.PID) (libpf.String, error) {
	cgroupFile, err := os.Open(ProcPath(pid, "cgroup"))
	if err != nil {
		return libpf.NullString, err
	}
	defer cgroupFile.Close()

	return parseContainerID(cgroupFile), nil
}

func trimMappingPath(path string) string {
	// Trim the deleted indication from the path.
	// See path_with_deleted in linux/fs/d_path.c
	path = strings.TrimSuffix(path, " (deleted)")
	if path == "/dev/zero" {
		// Some JIT engines map JIT area from /dev/zero
		// make it anonymous.
		return ""
	}
	return path
}

func iterateMappings(mapsFile io.Reader, callback func(m RawMapping) bool) (uint32, error) {
	numParseErrors := uint32(0)
	scanner := bufio.NewScanner(mapsFile)
	scanBuf := bufPool.Get().(*[]byte)
	if scanBuf == nil {
		return 0, errors.New("failed to get memory from sync pool")
	}
	defer func() {
		// Reset memory and return it for reuse.
		for j := 0; j < len(*scanBuf); j++ {
			(*scanBuf)[j] = 0x0
		}
		bufPool.Put(scanBuf)
	}()

	scanner.Buffer(*scanBuf, 8192)
	for scanner.Scan() {
		var fields [6]string
		var addrs [2]string
		var devs [2]string

		// WARNING: line (and all substrings derived from it, including the
		// Path field of the emitted RawMapping) points into scanBuf which is
		// recycled after iteration. Callers must intern Path (libpf.Intern)
		// before storing.
		line := pfunsafe.ToString(scanner.Bytes())
		if stringutil.FieldsN(line, fields[:]) < 5 {
			numParseErrors++
			continue
		}
		if stringutil.SplitN(fields[0], "-", addrs[:]) < 2 {
			numParseErrors++
			continue
		}

		mapsFlags := fields[1]
		if len(mapsFlags) < 3 {
			numParseErrors++
			continue
		}
		flags := elf.ProgFlag(0)
		if mapsFlags[0] == 'r' {
			flags |= elf.PF_R
		}
		if mapsFlags[1] == 'w' {
			flags |= elf.PF_W
		}
		if mapsFlags[2] == 'x' {
			flags |= elf.PF_X
		}

		// Ignore non-readable and non-executable mappings
		if flags&(elf.PF_R|elf.PF_X) == 0 {
			continue
		}
		inode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			log.Debugf("inode: failed to convert %s to uint64: %v", fields[4], err)
			numParseErrors++
			continue
		}

		if stringutil.SplitN(fields[3], ":", devs[:]) < 2 {
			numParseErrors++
			continue
		}
		major, err := strconv.ParseUint(devs[0], 16, 64)
		if err != nil {
			log.Debugf("major device: failed to convert %s to uint64: %v", devs[0], err)
			numParseErrors++
			continue
		}
		minor, err := strconv.ParseUint(devs[1], 16, 64)
		if err != nil {
			log.Debugf("minor device: failed to convert %s to uint64: %v", devs[1], err)
			numParseErrors++
			continue
		}
		device := major<<8 + minor

		var path string
		if inode == 0 {
			if fields[5] == "[vdso]" {
				// Map to something filename looking with synthesized inode
				path = VdsoPathName
				device = 0
				inode = vdsoInode
			} else if fields[5] == "" {
				// This is an anonymous mapping, keep it
			} else {
				// Ignore other mappings that are invalid, non-existent or are special pseudo-files
				continue
			}
		} else {
			path = trimMappingPath(fields[5])
		}

		vaddr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			log.Debugf("vaddr: failed to convert %s to uint64: %v", addrs[0], err)
			numParseErrors++
			continue
		}
		vend, err := strconv.ParseUint(addrs[1], 16, 64)
		if err != nil {
			log.Debugf("vend: failed to convert %s to uint64: %v", addrs[1], err)
			numParseErrors++
			continue
		}
		length := vend - vaddr

		fileOffset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			log.Debugf("fileOffset: failed to convert %s to uint64: %v", fields[2], err)
			numParseErrors++
			continue
		}

		if !callback(RawMapping{
			Vaddr:      vaddr,
			Length:     length,
			Flags:      flags,
			FileOffset: fileOffset,
			Device:     device,
			Inode:      inode,
			Path:       path,
		}) {
			return numParseErrors, ErrCallbackStopped
		}
	}
	return numParseErrors, scanner.Err()
}

func (sp *systemProcess) IterateMappings(callback func(m RawMapping) bool) (uint32, error) {
	mapsFile, err := os.Open(ProcPath(sp.pid, "maps"))
	if err != nil {
		return 0, err
	}
	defer mapsFile.Close()

	fileToMapping := make(map[string]*RawMapping)
	gotMappings := false

	collectForOpenELF := func(m RawMapping) bool {
		gotMappings = true
		if m.IsExecutable() || m.IsVDSO() {
			stored := m
			stored.Path = libpf.Intern(m.Path).String()
			fileToMapping[stored.Path] = &stored
		}
		return callback(m)
	}

	numParseErrors, err := iterateMappings(mapsFile, collectForOpenELF)
	if err != nil {
		return numParseErrors, err
	}

	if !gotMappings {
		// We could test for main thread exit here by checking for zombie state
		// in /proc/sp.pid/stat but it's simpler to assume that this is the case
		// and try extracting mappings for a different thread. Since we stopped
		// processing /proc at agent startup, it's not possible that the agent
		// will sample a process without mappings
		log.Debugf("PID: %v main thread exit", sp.pid)
		sp.mainThreadExit = true

		if sp.pid == sp.tid {
			return numParseErrors, ErrNoMappings
		}

		log.Debugf("TID: %v extracting mappings", sp.tid)
		mapsFileAlt, err := os.Open(fmt.Sprintf("%s/%d/task/%d/maps", ProcFSRoot, sp.pid, sp.tid))
		// On all errors resulting from trying to get mappings from a different thread,
		// return ErrNoMappings which will keep the PID tracked in processmanager and
		// allow for a future iteration to try extracting mappings from a different thread.
		// This is done to deal with race conditions triggered by thread exits (we do not want
		// the agent to unload process metadata when a thread exits but the process is still
		// alive).
		if err != nil {
			return numParseErrors, ErrNoMappings
		}
		defer mapsFileAlt.Close()
		numParseErrors, err := iterateMappings(mapsFileAlt, collectForOpenELF)
		if err != nil || !gotMappings {
			return numParseErrors, ErrNoMappings
		}
	}

	sp.fileToMapping = fileToMapping
	return numParseErrors, nil
}

func (sp *systemProcess) GetThreads() ([]ThreadInfo, error) {
	return nil, errors.New("not implemented")
}

func (sp *systemProcess) Close() error {
	return nil
}

func (sp *systemProcess) GetRemoteMemory() remotememory.RemoteMemory {
	return sp.remoteMemory
}

func (sp *systemProcess) extractMapping(m *RawMapping) (*bytes.Reader, error) {
	data := make([]byte, m.Length)
	_, err := sp.remoteMemory.ReadAt(data, int64(m.Vaddr))
	if err != nil {
		return nil, fmt.Errorf("unable to extract mapping at %#x from PID %d",
			m.Vaddr, sp.pid)
	}
	return bytes.NewReader(data), nil
}

func (sp *systemProcess) getMappingFile(m *RawMapping) string {
	if !m.IsFileBacked() {
		return ""
	}
	if sp.mainThreadExit {
		// Neither /proc/sp.pid/map_files nor /proc/sp.pid/task/sp.tid/map_files
		// nor /proc/sp.pid/root exist if main thread has exited, so we use the
		// mapping path directly under the sp.tid root.
		rootPath := fmt.Sprintf("%s/%v/task/%v/root", ProcFSRoot, sp.pid, sp.tid)
		return path.Join(rootPath, m.Path)
	}
	return fmt.Sprintf("%s/%v/map_files/%x-%x", ProcFSRoot, sp.pid, m.Vaddr, m.Vaddr+m.Length)
}

func (sp *systemProcess) OpenMappingFile(m *RawMapping) (ReadAtCloser, error) {
	filename := sp.getMappingFile(m)
	if filename == "" {
		return nil, errors.New("no backing file for anonymous memory")
	}
	return os.Open(filename)
}

func (sp *systemProcess) GetMappingFileLastModified(m *RawMapping) int64 {
	filename := sp.getMappingFile(m)
	if filename != "" {
		var st unix.Stat_t
		if err := unix.Stat(filename, &st); err == nil {
			return st.Mtim.Nano()
		}
	}
	return 0
}

// vdsoFileID caches the VDSO FileID. This assumes there is single instance of
// VDSO for the system.
var vdsoFileID libpf.FileID

func (sp *systemProcess) CalculateMappingFileID(m *RawMapping) (libpf.FileID, error) {
	if m.IsVDSO() {
		if vdsoFileID != (libpf.FileID{}) {
			return vdsoFileID, nil
		}
		vdso, err := sp.extractMapping(m)
		if err != nil {
			return libpf.FileID{}, fmt.Errorf("failed to extract VDSO: %v", err)
		}
		vdsoFileID, err = libpf.FileIDFromExecutableReader(vdso)
		return vdsoFileID, err
	}
	return libpf.FileIDFromExecutableFile(sp.getMappingFile(m))
}

func (sp *systemProcess) OpenELF(file string) (*pfelf.File, error) {
	// Always open via map_files as it can open deleted files if available.
	// No fallback is attempted:
	// - if the process exited, the fallback will error also (/proc/>PID> is gone)
	// - if the error is due to ELF content, same error will occur in both cases
	// - if the process unmapped the ELF, its data is no longer needed
	if m, ok := sp.fileToMapping[file]; ok {
		if m.IsVDSO() {
			vdso, err := sp.extractMapping(m)
			if err != nil {
				return nil, fmt.Errorf("failed to extract VDSO: %v", err)
			}
			return pfelf.NewFile(vdso, 0, false)
		}
		return pfelf.Open(sp.getMappingFile(m))
	}

	// Fall back to opening the file using the process specific root
	return pfelf.Open(path.Join(ProcFSRoot, strconv.Itoa(int(sp.pid)), "root", file))
}
