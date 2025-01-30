// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package version contains variables such as project name, tag and sha. It's a proper alternative to using
// -ldflags '-X ...'.
package version

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

var (
	// Tag declares project git tag.
	//go:embed data/tag
	Tag string
	// SHA declares project git SHA.
	//go:embed data/sha
	SHA string
	// Name declares project name.
	Name = func() string {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			panic("cannot read build info, something is very wrong")
		}

		// Check if siderolabs project
		prefix := "github.com/siderolabs/"
		if strings.HasPrefix(info.Path, prefix) {
			tail := info.Path[len(prefix):]

			before, _, found := strings.Cut(tail, "/")
			if found {
				return before
			}
		}

		// We could return a proper full path here, but it could be seen as a privacy violation.
		return "community-project"
	}()
)
