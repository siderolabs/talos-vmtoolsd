// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/equinix-ms/go-vmw-guestrpc/pkg/nanotoolbox"

	"github.com/siderolabs/talos-vmtoolsd/internal/nicinfo"
	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
)

const (
	ipAddressEntryV4 = int32(1) // IAT_IPV4
	ipAddressEntryV6 = int32(2) // IAT_IPV6
)

const iasPreferred = int32(1) // IAS_PREFERRED

const unknown = `UNKNOWN`

const maxNICs = 16

// GuestInfo represents the guestinfo integration.
type GuestInfo struct {
	talos   *talosconnection.TalosAPIConnection
	logger  *slog.Logger
	service *nanotoolbox.Service
}

// NewGuestInfo initializes the guestinfo integration.
func NewGuestInfo(logger *slog.Logger, talos *talosconnection.TalosAPIConnection, service *nanotoolbox.Service) *GuestInfo {
	logger.Debug("initializing")

	g := &GuestInfo{
		logger:  logger,
		talos:   talos,
		service: service,
	}

	return g
}

// functions that send arbitrary commands/info

// setGuestInfo sets guest property.
func (g *GuestInfo) infoSet(kind string, value string) {
	ok, err := g.service.InfoSet(kind, value)

	g.logger.Debug("received", "ok", ok, "err", err)

	if err != nil {
		g.logger.Error("error sending guest info", "err", err)
	}
}

// convenience wrappers, as they'll get called from different handlers

// setGuestInfoString wraps rpci.SetGuestInfo, but for strings. Less DRY.
func (g *GuestInfo) setGuestInfoString(kind nanotoolbox.GuestInfoID, fn func() string) {
	l := g.logger.With("guest_info_kind", kind.String())
	strVal := fn()

	l.Debug("setting guestinfo string", "str", strVal)
	g.service.SetGuestInfo(kind, []byte(strVal))
}

// setDNSName fetches the DNSName from Talos and sets it.
func (g *GuestInfo) setDNSName() {
	g.setGuestInfoString(nanotoolbox.GuestInfoDNSName, func() string {
		if hostname := g.talos.Hostname(); hostname != "" {
			return hostname
		}

		return unknown
	})
}

// setOSNameFull fetches the full OS name/version from Talos and sets it.
func (g *GuestInfo) setOSNameFull() {
	g.setGuestInfoString(nanotoolbox.GuestInfoOSNameFull, func() string {
		if osname := g.talos.OSVersion(); osname != "" {
			return osname
		}

		return unknown
	})
}

// setOSName fetches the short OS name/version from Talos and sets it.
func (g *GuestInfo) setOSName() {
	g.setGuestInfoString(nanotoolbox.GuestInfoOSName, func() string {
		if osname := g.talos.OSVersionShort(); osname != "" {
			return osname
		}

		return unknown
	})
}

// setUptime fetches the uptime from Talos and sets it.
func (g *GuestInfo) setUptime() {
	g.setGuestInfoString(nanotoolbox.GuestInfoUptime, func() string {
		return strconv.Itoa(g.talos.Uptime() * 100)
	})
}

// prefixToIAE converts a `netip.Prefix` into a govmomi `IPAddressEntry`.
// yes, there is a function `AddIP`, but it needs a `net.Addr` that is castable into `net.IPNet`
// and Talos yields `netip.Prefix`, and it is a pain to convert these.
func prefixToIAE(p netip.Prefix) nicinfo.IPAddressEntry {
	kind := ipAddressEntryV4

	if p.Addr().Is6() {
		kind = ipAddressEntryV6
	}

	status := iasPreferred
	e := nicinfo.IPAddressEntry{
		Address: nicinfo.TypedIPAddress{
			Type:    kind,
			Address: p.Addr().AsSlice(),
		},
		PrefixLength: uint32(p.Bits()),
		Status:       &status,
	}

	return e
}

// setIPAddressV3 fetches the list of nics (name, mac, addresses) ans sets it using XDR encoding.
func (g *GuestInfo) setIPAddressV3() {
	info := nicinfo.New()

	// fetch NIC info
	for _, talosNic := range g.talos.NetInterfaces() {
		g.logger.Debug("creating NIC entry", "name", talosNic.Name, "mac", talosNic.Mac)
		nic := nicinfo.GuestNicV3{MacAddress: talosNic.Mac}

		for _, addr := range talosNic.Addrs {
			g.logger.Debug("adding IP address", "addr", addr, "nic", talosNic.Name)
			iae := prefixToIAE(addr)
			nic.IPs = append(nic.IPs, iae)
		}

		info.V3.Nics = append(info.V3.Nics, nic)

		if len(info.V3.Nics) >= maxNICs {
			g.logger.Warn("maximum number of NICs reached", "max", maxNICs)

			break
		}
	}

	if hostname := g.talos.Hostname(); hostname != "" {
		info.V3.DNSConfigInfo = &nicinfo.DNSConfigInfo{HostName: &hostname}
	}

	infoXDR, err := nicinfo.EncodeXDR(info)
	if err != nil {
		g.logger.Error("error encoding NIC info to XDR", "err", err)

		return
	}

	g.logger.Debug("setting info about nics", "len", len(info.V3.Nics))

	g.service.SetGuestInfo(nanotoolbox.GuestInfoIPAddressV3, infoXDR)
}

// primaryIP using very complex logic to carefully calculate the primary IP address using AI, weighted logic and kittens.
func (g *GuestInfo) primaryIP() string {
	// find the first interface with an address and return it. Assume that that's the "primary IP"
	for _, nic := range g.talos.NetInterfaces() {
		for _, addr := range nic.Addrs {
			return addr.Addr().String()
		}
	}

	g.logger.Warn("no IP addresses found from Talos API")

	return "unknown"
}

// Register registers all handlers, options and capabilities.
func (g *GuestInfo) Register() {
	g.logger.Debug("registering")
	// reset handlers
	g.service.RegisterResetHandler(func() {
		g.setDNSName()
		g.setOSNameFull()
		g.setOSName()
		g.setUptime()
		g.setIPAddressV3()
	})

	// option handlers
	g.service.RegisterOptionHandler("broadcastIP", func(string, string) {
		g.infoSet("guestinfo.ip", g.primaryIP())
		g.setIPAddressV3()
	})

	// ping handlers
	g.service.RegisterCommandHandler("ping", func([]byte) ([]byte, error) {
		g.setDNSName()
		g.setOSNameFull()
		g.setOSName()
		g.setUptime()

		return nil, nil
	})

	// As stated in guestInfoServer.c, VMX expects uptime information in response
	// to the capabilities request.
	g.service.AddCapability(fmt.Sprintf("SetGuestInfo  %d %d", nanotoolbox.GuestInfoUptime, g.talos.Uptime()*100))
}
