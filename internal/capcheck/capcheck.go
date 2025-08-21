// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package capcheck implements CheckCapabilities
package capcheck

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// HasCapability checks natively if a given LINUX capability is granted
// Capability (position) is in bits, only for reference
// https://pkg.go.dev/github.com/syndtr/gocapability/capability#pkg-constants
func HasCapability(capabilityBit int8) (bool, error) {
	procStatus, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false, fmt.Errorf("error reading /proc/self/status: %w", err)
	}

	for _, line := range strings.Split(string(procStatus), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return false, fmt.Errorf("invalid CapEff line format")
			}
			// read as hexadecimal number (base 16).
			val, err := strconv.ParseUint(parts[1], 16, 64)
			if err != nil {
				return false, fmt.Errorf("error parsing CapEff value: %w", err)
			}
			// Create bitmask and bitwise to determine if capability (as decicmal) is set
			if val&(1<<capabilityBit) != 0 {
				return true, nil
			}

			return false, nil
		}
	}

	return false, fmt.Errorf("capEff line not found")
}
