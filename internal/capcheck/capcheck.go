// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package capcheck

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CheckCapabilities checks natively if a given LINUX capability is granted
// Capability (position) is in bits, only for reference
// https://pkg.go.dev/github.com/syndtr/gocapability/capability#pkg-constants

func CheckCapabilities(capability_bit int8) (error) {
    proc_status, err := os.ReadFile("/proc/self/status")
    if err != nil {
        return fmt.Errorf("error reading /proc/self/status: %v", err)
    }

    for _, line := range strings.Split(string(proc_status), "\n") {
        if strings.HasPrefix(line, "CapEff:") {
            parts := strings.Fields(line)
            if len(parts) < 2 {
                return fmt.Errorf("invalid CapEff line format")
            }
            // read as hexadecimal number (base 16).
            val, err := strconv.ParseUint(parts[1], 16, 64)
            if err != nil {
                return fmt.Errorf("error parsing CapEff value: %v", err)
            }
            // Create bitmask and bitwise to determine if capability (as decicmal) is set
            if val&(1<<capability_bit) != 0 {
                return nil
            }
            return fmt.Errorf("Capability (%v) is not granted inside current environment!", capability_bit)
        }
    }
    return fmt.Errorf("CapEff line not found")
}
