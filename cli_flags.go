// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/peterbourgon/ff/v3"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	// Default values for CLI flags
	defaultArgSamplesPerSecond    = 20
	defaultArgReporterInterval    = 5.0 * time.Second
	defaultArgReporterJitter      = 0.2
	defaultArgMonitorInterval     = 5.0 * time.Second
	defaultClockSyncInterval      = 3 * time.Minute
	defaultProbabilisticThreshold = tracer.ProbabilisticThresholdMax
	defaultProbabilisticInterval  = 1 * time.Minute
	defaultArgSendErrorFrames     = false
	defaultOffCPUThreshold        = 0
	defaultEnvVarsValue           = ""

	// This is the X in 2^(n + x) where n is the default hardcoded map size value
	defaultArgMapScaleFactor = 0

	defaultTargetPID  = 0
	defaultDuration   = 0
	defaultOutputFile = ""
	defaultFileType   = "folded"
)

// Help strings for command line arguments
var (
	noKernelVersionCheckHelp = "Disable checking kernel version for eBPF support. " +
		"Use at your own risk, to run the agent on older kernels with backported eBPF features."
	copyrightHelp      = "Show copyright and short license text."
	collAgentAddrHelp  = "The collection agent address in the format of host:port."
	verboseModeHelp    = "Enable verbose logging and debugging capabilities."
	tracersHelp        = "Comma-separated list of interpreter tracers to include."
	mapScaleFactorHelp = fmt.Sprintf("Scaling factor for eBPF map sizes. "+
		"Every increase by 1 doubles the map size. Increase if you see eBPF map size errors. "+
		"Default is %d corresponding to 4GB of executable address space, max is %d.",
		defaultArgMapScaleFactor, config.MaxArgMapScaleFactor)
	disableTLSHelp             = "Disable encryption for data in transit."
	bpfVerifierLogLevelHelp    = "Log level of the eBPF verifier output (0,1,2). Default is 0."
	versionHelp                = "Show version."
	probabilisticThresholdHelp = fmt.Sprintf("If set to a value between 1 and %d will enable "+
		"probabilistic profiling: "+
		"every probabilistic-interval a random number between 0 and %d is "+
		"chosen. If the given probabilistic-threshold is greater than this "+
		"random number, the agent will collect profiles from this system for "+
		"the duration of the interval.",
		tracer.ProbabilisticThresholdMax-1, tracer.ProbabilisticThresholdMax-1)
	probabilisticIntervalHelp = "Time interval for which probabilistic profiling will be " +
		"enabled or disabled."
	pprofHelp            = "Listening address (e.g. localhost:6060) to serve pprof information."
	samplesPerSecondHelp = "Set the frequency (in Hz) of stack trace sampling."
	reporterIntervalHelp = "Set the reporter's interval in seconds."
	reporterJitterHelp   = fmt.Sprintf("Set the jitter applied to the reporter's interval as a fraction. "+
		"Valid values are in the range [0..1]. "+
		"Default is %.1f.",
		defaultArgReporterJitter)
	monitorIntervalHelp   = "Set the monitor interval in seconds."
	clockSyncIntervalHelp = "Set the sync interval with the realtime clock. " +
		"If zero, monotonic-realtime clock sync will be performed once, " +
		"on agent startup, but not periodically."
	sendErrorFramesHelp = "Send error frames (devfiler only, breaks Kibana)"
	sendIdleFramesHelp  = "Unwind and report idle states of the Linux kernel."
	offCPUThresholdHelp = fmt.Sprintf("The probability for an off-cpu event being recorded. "+
		"Valid values are in the range [0..1]. 0 disables off-cpu profiling. "+
		"Default is %d.",
		defaultOffCPUThreshold)
	envVarsHelp = "Comma separated list of environment variables that will be reported with the" +
		"captured profiling samples."
	probeLinkHelper = "Attach a probe to a symbol of an executable. " +
		"Expected format: probe_type:target[:symbol]. probe_type can be kprobe, kretprobe, uprobe, or uretprobe."
	loadProbeHelper = "Load generic eBPF program that can be attached externally to " +
		"various user or kernel space hooks."
	targetPIDHelp  = "Target process PID to profile. 0 means profile all processes."
	durationHelp   = "Profiling duration (e.g. 30s, 5m). After this duration, the agent " +
		"will automatically stop and write the output file."
	outputFileHelp = "Output file path for profiling results (protobuf format). " +
		"Required when -duration is set."
	fileTypeHelp = "Output file format type. Supported values: 'folded' (default, for flamegraph.pl), " +
		"'jfr' (JDK Flight Recorder format, for JMC or jfr tool), " +
		"and 'pprof' (pprof format, for go tool pprof or pprof CLI)."
	hostProcHelp = "Path to the host's /proc filesystem. " +
		"When running inside a container, mount the host's /proc to a path inside the container " +
		"(e.g. -v /proc:/host/proc:ro) and set this flag to that path (e.g. -host-proc=/host/proc). " +
		"This allows the profiler to access all host processes. " +
		"Defaults to /proc (suitable for running directly on the host). " +
		"Can also be set via HOST_PROC environment variable."
	enableCudaHelp = "Enable CUDA USDT probe for GPU kernel correlation. " +
		"Requires Linux 5.4+ kernel. Only effective in CPU sampling mode."
	cudaBinaryHelp = "Path to the binary (e.g. shared library .so) containing the USDT probe " +
		"parcagpu:cuda_correlation. If not specified, defaults to /proc/<pid>/exe."
	enableTimeHelp = "Enable converting CPU sampling counts to time. " +
		"When enabled, the sample count for CPU profiling is converted to time using the unit specified by -time-unit. " +
		"Only affects CPU sampling, not USDT or uprobe events. " +
		"Defaults to true when -enable-cuda is set, otherwise defaults to false."
	timeUnitHelp = "Set the time unit for -enable-time conversion. " +
		"Supported values: 'ns' (nanoseconds, default), 'us' (microseconds), 'ms' (milliseconds). " +
		"Only effective when -enable-time is enabled."
)

// Package-scope variable, so that conditionally compiled other components can refer
// to the same flagset.

func parseArgs() (*controller.Config, error) {
	var args controller.Config

	fs := flag.NewFlagSet("ebpf-profiler", flag.ExitOnError)

	// Please keep the parameters ordered alphabetically in the source-code.
	fs.UintVar(&args.BPFVerifierLogLevel, "bpf-log-level", 0, bpfVerifierLogLevelHelp)

	fs.StringVar(&args.CollAgentAddr, "collection-agent", "", collAgentAddrHelp)
	fs.BoolVar(&args.Copyright, "copyright", false, copyrightHelp)

	fs.BoolVar(&args.DisableTLS, "disable-tls", false, disableTLSHelp)

	fs.UintVar(&args.MapScaleFactor, "map-scale-factor",
		defaultArgMapScaleFactor, mapScaleFactorHelp)

	fs.DurationVar(&args.MonitorInterval, "monitor-interval", defaultArgMonitorInterval,
		monitorIntervalHelp)

	fs.DurationVar(&args.ClockSyncInterval, "clock-sync-interval", defaultClockSyncInterval,
		clockSyncIntervalHelp)

	fs.BoolVar(&args.NoKernelVersionCheck, "no-kernel-version-check", false,
		noKernelVersionCheckHelp)

	fs.StringVar(&args.PprofAddr, "pprof", "", pprofHelp)

	fs.DurationVar(&args.ProbabilisticInterval, "probabilistic-interval",
		defaultProbabilisticInterval, probabilisticIntervalHelp)
	fs.UintVar(&args.ProbabilisticThreshold, "probabilistic-threshold",
		defaultProbabilisticThreshold, probabilisticThresholdHelp)

	fs.DurationVar(&args.ReporterInterval, "reporter-interval", defaultArgReporterInterval,
		reporterIntervalHelp)
	fs.Float64Var(&args.ReporterJitter, "reporter-jitter", defaultArgReporterJitter,
		reporterJitterHelp)

	fs.IntVar(&args.SamplesPerSecond, "samples-per-second", defaultArgSamplesPerSecond,
		samplesPerSecondHelp)

	fs.BoolVar(&args.SendErrorFrames, "send-error-frames", defaultArgSendErrorFrames,
		sendErrorFramesHelp)
	fs.BoolVar(&args.SendIdleFrames, "send-idle-frames", false, sendIdleFramesHelp)

	fs.StringVar(&args.Tracers, "t", "all", "Shorthand for -tracers.")
	fs.StringVar(&args.Tracers, "tracers", "all", tracersHelp)

	fs.BoolVar(&args.VerboseMode, "v", false, "Shorthand for -verbose.")
	fs.BoolVar(&args.VerboseMode, "verbose", false, verboseModeHelp)
	fs.BoolVar(&args.Version, "version", false, versionHelp)

	fs.Float64Var(&args.OffCPUThreshold, "off-cpu-threshold",
		defaultOffCPUThreshold, offCPUThresholdHelp)

	fs.StringVar(&args.IncludeEnvVars, "env-vars", defaultEnvVarsValue, envVarsHelp)

	fs.Func("probe-link", probeLinkHelper, func(link string) error {
		args.ProbeLinks = append(args.ProbeLinks, link)
		return nil
	})

	fs.BoolVar(&args.LoadProbe, "load-probe", false, loadProbeHelper)

	fs.IntVar(&args.TargetPID, "pid", defaultTargetPID, targetPIDHelp)
	fs.DurationVar(&args.Duration, "duration", defaultDuration, durationHelp)
	fs.StringVar(&args.OutputFile, "output", defaultOutputFile, outputFileHelp)
	fs.StringVar(&args.FileType, "file-type", defaultFileType, fileTypeHelp)

	fs.BoolVar(&args.EnableCuda, "enable-cuda", false, enableCudaHelp)
	fs.StringVar(&args.CudaBinary, "cuda-binary", "", cudaBinaryHelp)
	fs.StringVar(&args.HostProc, "host-proc", "/proc", hostProcHelp)

	var enableTime bool
	fs.BoolVar(&enableTime, "enable-time", false, enableTimeHelp)

	var timeUnit string
	fs.StringVar(&timeUnit, "time-unit", "ns", timeUnitHelp)

	fs.Usage = func() {
		fs.PrintDefaults()
	}

	args.Fs = fs

	args.ErrorMode = config.PropagateError

	err := ff.Parse(fs, os.Args[1:],
		ff.WithEnvVarPrefix("OTEL_PROFILING_AGENT"),
		ff.WithConfigFileFlag("config"),
		ff.WithConfigFileParser(ff.PlainParser),
		// This will ignore configuration file (only) options that the current HA
		// does not recognize.
		ff.WithIgnoreUndefined(true),
		ff.WithAllowMissingConfigFile(true),
	)
	if err != nil {
		return nil, err
	}

	// 处理 enable-time 的默认值逻辑：
	// 如果用户显式设置了 -enable-time，使用用户的值；
	// 否则，当 -enable-cuda 开启时默认开启 enable-time。
	enableTimeExplicitlySet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "enable-time" {
			enableTimeExplicitlySet = true
		}
	})

	if enableTimeExplicitlySet {
		args.EnableTime = &enableTime
	} else if args.EnableCuda {
		// -enable-cuda 开启时，enable-time 默认为 true
		defaultEnableTime := true
		args.EnableTime = &defaultEnableTime
	}
	// 否则 args.EnableTime 保持 nil（等同于 false）

	// 设置时间单位，默认为 ns
	if timeUnit == "" {
		timeUnit = "ns"
	}
	if !support.ValidTimeUnit(timeUnit) {
		return nil, fmt.Errorf("invalid time-unit %q, supported values: ns, us, ms", timeUnit)
	}
	args.TimeUnit = support.TimeUnit(timeUnit)

	return &args, nil
}
