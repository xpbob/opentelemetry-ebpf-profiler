// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	//nolint:gosec
	_ "net/http/pprof"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/vc"
	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// Short copyright / license text for eBPF code
var copyright = `Copyright The OpenTelemetry Authors.

For the eBPF code loaded by Universal Profiling Agent into the kernel,
the following license applies (GPLv2 only). You can obtain a copy of the GPLv2 code at:
https://go.opentelemetry.io/ebpf-profiler/tree/main/support/ebpf

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 only,
as published by the Free Software Foundation;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details:

https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
`

type exitCode int

const (
	exitSuccess exitCode = 0
	exitFailure exitCode = 1

	// Go 'flag' package calls os.Exit(2) on flag parse errors, if ExitOnError is set
	exitParseError exitCode = 2
)

func main() {
	os.Exit(int(mainWithExitCode()))
}

func mainWithExitCode() exitCode {
	cfg, err := parseArgs()
	if err != nil {
		log.Errorf("Failure to parse arguments: %v", err)
		return exitParseError
	}

	if cfg.Copyright {
		fmt.Print(copyright)
		return exitSuccess
	}

	if cfg.Version {
		fmt.Printf("%s\n", vc.Version())
		return exitSuccess
	}

	if cfg.VerboseMode {
		log.SetLevel(slog.LevelDebug)
		// Dump the arguments in debug mode.
		cfg.Dump()
	}

	if err = cfg.Validate(); err != nil {
		log.Error(err)
		return exitFailure
	}

	// Context to drive main goroutine and the Tracer monitors.
	ctx, mainCancel := signal.NotifyContext(context.Background(),
		unix.SIGINT, unix.SIGTERM, unix.SIGABRT)
	defer mainCancel()

	if cfg.PprofAddr != "" {
		go func() {
			//nolint:gosec
			if err = http.ListenAndServe(cfg.PprofAddr, nil); err != nil {
				log.Errorf("Serving pprof on %s failed: %s", cfg.PprofAddr, err)
			}
		}()
	}

	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)

	metrics.Start(noop.Meter{})

	// 设置 procfs 根路径（必须在 NewFileReporter 之前，因为 resolveHostPID 依赖此设置）。
	// 支持通过 -host-proc 参数指定（容器场景），也支持通过 HOST_PROC 环境变量设置。
	// 优先级：命令行参数 > 环境变量 > 默认值 "/proc"
	hostProc := cfg.HostProc
	if hostProc == "" || hostProc == "/proc" {
		if envProc := os.Getenv("HOST_PROC"); envProc != "" {
			hostProc = envProc
		}
	}
	if hostProc != "" && hostProc != "/proc" {
		// 验证路径是否存在
		if info, err := os.Stat(hostProc); err != nil {
			log.Warnf("指定的 host-proc 路径 %s 不存在或无法访问: %v，将使用默认 /proc", hostProc, err)
		} else if !info.IsDir() {
			log.Warnf("指定的 host-proc 路径 %s 不是目录，将使用默认 /proc", hostProc)
		} else {
			process.ProcFSRoot = hostProc
			log.Infof("Using host procfs at %s (container mode)", hostProc)
		}
	}

	// 统一做 PID 转换：将用户传入的 namespace PID 转换为宿主机 PID。
	// 必须在设置 ProcFSRoot 之后、创建 reporter 和 controller 之前执行，
	// 确保 FileReporter 的 PID 过滤和 StartCudaProfiling 的 uprobe 挂载都使用宿主机 PID。
	if cfg.TargetPID > 0 {
		resolvedPID := process.ResolveHostPID(cfg.TargetPID)
		if resolvedPID != cfg.TargetPID {
			log.Infof("目标 PID 已从 %d 转换为宿主机 PID %d", cfg.TargetPID, resolvedPID)
			cfg.TargetPID = resolvedPID
		}
	}

	// 判断是否为定时采样模式（指定了 -duration 和 -output）
	isTimedMode := cfg.Duration > 0 && cfg.OutputFile != ""

	var rep reporter.Reporter
	if isTimedMode {
		// 定时采样模式：使用 FileReporter，支持 PID 过滤和文件输出
		fileRep, fileErr := reporter.NewFileReporter(&reporter.Config{
			Name:             os.Args[0],
			Version:          vc.Version(),
			SamplesPerSecond: cfg.SamplesPerSecond,
			EnableTime:       cfg.IsEnableTime(),
		}, cfg.TargetPID, cfg.OutputFile, reporter.FileType(cfg.FileType))
		if fileErr != nil {
			log.Error(fileErr)
			return exitFailure
		}
		rep = fileRep
		log.Infof("定时采样模式: PID=%d, 持续时间=%v, 输出文件=%s, 格式=%s",
			cfg.TargetPID, cfg.Duration, cfg.OutputFile, cfg.FileType)
	} else {
		// 常规模式：使用 OTLP Reporter 上报到后端
		otlpRep, otlpErr := reporter.NewOTLP(&reporter.Config{
			Name:                   os.Args[0],
			Version:                vc.Version(),
			CollAgentAddr:          cfg.CollAgentAddr,
			DisableTLS:             cfg.DisableTLS,
			MaxRPCMsgSize:          32 << 20, // 32 MiB
			MaxGRPCRetries:         5,
			GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
			GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
			GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
			ReportInterval:         intervals.ReportInterval(),
			ReportJitter:           cfg.ReporterJitter,
			SamplesPerSecond:       cfg.SamplesPerSecond,
			EnableTime:             cfg.IsEnableTime(),
		})
		if otlpErr != nil {
			log.Error(otlpErr)
			return exitFailure
		}
		rep = otlpRep
	}
	cfg.Reporter = rep

	log.Infof("Starting OTEL profiling agent %s (revision %s, build timestamp %s)",
		vc.Version(), vc.Revision(), vc.BuildTimestamp())

	ctlr := controller.New(cfg)
	err = ctlr.Start(ctx)
	if err != nil {
		return failure("Failed to start agent controller: %v", err)
	}
	defer ctlr.Shutdown()

	if isTimedMode {
		// 定时采样模式：等待指定时间后自动停止
		log.Infof("采样将在 %v 后自动停止...", cfg.Duration)
		select {
		case <-time.After(cfg.Duration):
			log.Infof("采样时间 %v 已到，正在停止采集...", cfg.Duration)
		case <-ctx.Done():
			log.Info("收到终止信号，提前停止采集...")
		}

		// 当启用了 CUDA 时，执行三阶段停止：
		// 阶段 1：停止 CPU 采样和 cuda_correlation 探针，保留 kernel_executed
		// 阶段 2：等待 5 秒让 kernel_executed 继续消费匹配的 CUDA kernel 执行数据
		// 阶段 3：停止 kernel_executed，flush 所有 pending 数据，再生成文件
		if cfg.EnableCuda {
			log.Info("CUDA 模式：停止 CPU 采样和 cuda_correlation，保留 kernel_executed 继续消费...")
			ctlr.StopCPUAndCorrelation()

			log.Info("等待 5 秒让 kernel_executed 消费剩余的 CUDA kernel 执行数据...")
			select {
			case <-time.After(5 * time.Second):
				log.Info("等待完成")
			case <-ctx.Done():
				log.Info("收到终止信号，立即停止...")
			}

			// 阶段 3：停止 kernel_executed 探针
			pendingCount := ctlr.PendingCudaCorrelationCount()
			log.Infof("停止 kernel_executed 探针，当前剩余未匹配 correlation: %d", pendingCount)
			ctlr.StopKernelExecuted()

			// flush 所有未匹配的 pending correlation 数据
			log.Info("正在 flush 所有未匹配的 CUDA correlation 数据...")
			ctlr.FlushPendingCudaCorrelations()
			log.Info("CUDA 数据消费完成，正在生成结果文件...")
		}
	} else {
		// 常规模式：等待信号终止
		<-ctx.Done()
	}

	log.Info("Exiting ...")
	return exitSuccess
}

func failure(msg string, args ...any) exitCode {
	log.Errorf(msg, args...)
	return exitFailure
}
