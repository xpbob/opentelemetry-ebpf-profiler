// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// enableTime 开启后，将 CPU 采样的采样次数转换为时间。
	enableTime bool

	// timeUnit 时间转化单位。
	timeUnit support.TimeUnit
}

func New(samplesPerSecond int, extra samples.SampleAttrProducer, enableTime bool, timeUnit support.TimeUnit) (*Pdata, error) {
	return &Pdata{
		samplesPerSecond:    samplesPerSecond,
		ExtraSampleAttrProd: extra,
		enableTime:          enableTime,
		timeUnit:            timeUnit,
	}, nil
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
}
