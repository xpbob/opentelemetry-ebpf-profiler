// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "go.opentelemetry.io/ebpf-profiler/support"

// TimeUnit 定义 enable-time 开启后的时间转化单位。
type TimeUnit string

const (
	// TimeUnitNS 纳秒（默认）
	TimeUnitNS TimeUnit = "ns"
	// TimeUnitUS 微秒
	TimeUnitUS TimeUnit = "us"
	// TimeUnitMS 毫秒
	TimeUnitMS TimeUnit = "ms"
)

// NanoDivisor 返回将纳秒转换为目标单位所需的除数。
func (u TimeUnit) NanoDivisor() int64 {
	switch u {
	case TimeUnitMS:
		return 1_000_000
	case TimeUnitUS:
		return 1_000
	case TimeUnitNS:
		return 1
	default:
		return 1
	}
}

// String 返回单位的字符串表示。
func (u TimeUnit) String() string {
	return string(u)
}

// ValidTimeUnit 校验时间单位是否合法。
func ValidTimeUnit(s string) bool {
	switch TimeUnit(s) {
	case TimeUnitNS, TimeUnitUS, TimeUnitMS:
		return true
	default:
		return false
	}
}
