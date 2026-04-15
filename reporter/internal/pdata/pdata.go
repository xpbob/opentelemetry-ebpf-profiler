// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// enableTime 开启后，将 CPU 采样的采样次数转换为时间（ms）。
	enableTime bool
}

func New(samplesPerSecond int, extra samples.SampleAttrProducer, enableTime bool) (*Pdata, error) {
	return &Pdata{
		samplesPerSecond:    samplesPerSecond,
		ExtraSampleAttrProd: extra,
		enableTime:          enableTime,
	}, nil
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
}
