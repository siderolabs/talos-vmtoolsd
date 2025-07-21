// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package talosconnection

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"google.golang.org/protobuf/types/known/emptypb"
)

func (c *TalosAPIConnection) osVersionInfo() (*machine.VersionInfo, error) {
	resp, err := c.client.Version(c.ctx)
	if err != nil || len(resp.Messages) == 0 {
		return nil, err
	}

	return resp.Messages[0].Version, nil
}

// OSVersion returns the OS version.
func (c *TalosAPIConnection) OSVersion() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.Error("error retrieving OS version information", "err", err)

		return "Talos unknown"
	}

	return fmt.Sprintf("Talos %s-%s", v.Tag, v.Sha)
}

// OSVersionShort returns the short OS version.
func (c *TalosAPIConnection) OSVersionShort() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.Error("error retrieving OS version information", "err", err)

		return "Talos"
	}

	return fmt.Sprintf("Talos %s", v.Tag)
}

// Hostname returns the hostname.
func (c *TalosAPIConnection) Hostname() string {
	resp, err := c.client.MachineClient.Hostname(c.ctx, &emptypb.Empty{})
	if err != nil || len(resp.Messages) == 0 {
		c.log.Error("error retrieving hostname", "err", err)

		return ""
	}

	return resp.Messages[0].Hostname
}

// Uptime returns the uptime according to Talos in seconds.
func (c *TalosAPIConnection) Uptime() int {
	resp, err := c.client.MachineClient.SystemStat(c.ctx, &emptypb.Empty{})
	if err != nil || len(resp.Messages) == 0 {
		c.log.Error("error retrieving system stats", "err", err)

		return 0
	}

	return int(time.Since(time.Unix(int64(resp.Messages[0].GetBootTime()), 0)).Round(time.Second).Seconds())
}

// NetInterface represents a network interface.
type NetInterface struct {
	Name  string
	Mac   string
	Addrs []netip.Prefix
}

// NetInterfaces returns the network interfaces.
func (c *TalosAPIConnection) NetInterfaces() (result []NetInterface) {
	addrMap := make(map[string][]*network.AddressStatusSpec)

	networkAddresses, err := safe.StateListAll[*network.AddressStatus](c.ctx, c.client.COSI)
	if err != nil {
		c.log.Error("error listing address status resources", "err", err)

		return nil
	}

	for addr := range networkAddresses.All() {
		linkName := addr.TypedSpec().LinkName
		addrMap[linkName] = append(addrMap[linkName], addr.TypedSpec())
	}

	linkStatuses, err := safe.StateListAll[*network.LinkStatus](c.ctx, c.client.COSI)
	if err != nil {
		c.log.Error("error listing link status resources", "err", err)

		return nil
	}

	for link := range linkStatuses.All() {
		if !link.TypedSpec().Physical() {
			continue
		}

		intf := NetInterface{
			Name: link.Metadata().ID(),
			Mac:  link.TypedSpec().HardwareAddr.String(),
		}

		for _, addr := range addrMap[intf.Name] {
			intf.Addrs = append(intf.Addrs, addr.Address)
		}

		result = append(result, intf)
	}

	return result
}
