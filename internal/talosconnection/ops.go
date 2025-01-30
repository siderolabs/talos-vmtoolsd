// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package talosconnection

// Shutdown shuts down the machine.
func (c *TalosAPIConnection) Shutdown() error {
	return c.client.Shutdown(c.ctx)
}

// Reboot reboots the machine.
func (c *TalosAPIConnection) Reboot() error {
	return c.client.Reboot(c.ctx)
}
