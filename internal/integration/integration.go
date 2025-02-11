// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package integration packages all the integrations between Talos Linux and VMWare
package integration

// Integration is the interface every integration should implement.
type Integration interface {
	Register()
}
