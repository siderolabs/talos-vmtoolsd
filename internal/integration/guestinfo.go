// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"

	"github.com/vmware/govmomi/toolbox"

	"github.com/siderolabs/talos-vmtoolsd/internal/talosconnection"
	"github.com/siderolabs/talos-vmtoolsd/internal/util"
	"github.com/siderolabs/talos-vmtoolsd/pkg/nanotoolbox"
)

type guestInfoID int

const (
	_ guestInfoID = iota
	// guestInfoDNSName is the guest info kind for the DNS name.
	guestInfoDNSName
	_ // IP v1
	_ // free disk space
	_ // build number
	// guestInfoOSNameFull is the guest info kind for the full OS name.
	guestInfoOSNameFull
	// guestInfoOSName is the guest info kind for the OS name.
	guestInfoOSName
	// guestInfoUptime is the guest uptime in 100s of seconds.
	guestInfoUptime
	_ // memory
	_ // IP v2
	// guestInfoIPAddressV3 is the guest info kind for the IP address.
	guestInfoIPAddressV3
	_ // OS detailed
)

const (
	ipAddressEntryV4 = int32(1) // IAT_IPV4
	ipAddressEntryV6 = int32(2) // IAT_IPV6
)

const iasPreferred = int32(1) // IAS_PREFERRED

const unknown = `UNKNOWN`

const maxNICs = 16

var guestInfos = map[guestInfoID]string{
	guestInfoDNSName:     "DNS name",
	guestInfoOSNameFull:  "full OS name",
	guestInfoOSName:      "short OS name",
	guestInfoUptime:      "uptime",
	guestInfoIPAddressV3: "IP address",
}

func (g guestInfoID) Name() string {
	return guestInfos[g]
}

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

// setGuestInfo sets a piece of information about the guest, used in a lot of handlers.
func (g *GuestInfo) setGuestInfo(kind guestInfoID, data []byte) {
	// NB: intentionally using two spaces as separator to match open-vm-tools
	l := g.logger.With("guest_info_kind", kind.Name())
	msg := append([]byte(fmt.Sprintf("SetGuestInfo  %d ", kind)), data...)
	util.TraceLog(l, "setting", "msg", string(msg))

	if _, err := g.service.Request(msg); err != nil {
		l.Error("error sending guest info", "err", err)
	}
}

// setGuestInfo also sets a piece of information about the guest, but in a different way.
func (g *GuestInfo) infoSet(kind string, value string) {
	l := g.logger.With("info-set_kind", kind)
	msg := []byte(fmt.Sprintf("info-set %s %s", kind, value))
	l.With("info-set_kind", kind).Debug("setting", "value", value, "msg", msg)

	if _, err := g.service.Request(msg); err != nil {
		l.Error("error sending guest info", "err", err)
	}
}

// convenience wrappers, as they'll get called from different handlers

// setString wraps setGuestInfo, but for strings.
func (g *GuestInfo) setString(kind guestInfoID, fn func() string) {
	s := fn()
	g.logger.With("guest_info_kind", kind.Name()).Debug("setting guestinfo string", "str", s)
	g.setGuestInfo(kind, []byte(s))
}

// setDNSName fetches the DNSName from Talos and sets it.
func (g *GuestInfo) setDNSName() {
	g.setString(guestInfoDNSName, func() string {
		if hostname := g.talos.Hostname(); hostname != "" {
			return hostname
		}

		return unknown
	})
}

// setOSNameFull fetches the full OS name/version from Talos and sets it.
func (g *GuestInfo) setOSNameFull() {
	g.setString(guestInfoOSNameFull, func() string {
		if osname := g.talos.OSVersion(); osname != "" {
			return osname
		}

		return unknown
	})
}

// setOSName fetches the short OS name/version from Talos and sets it.
func (g *GuestInfo) setOSName() {
	g.setString(guestInfoOSName, func() string {
		if osname := g.talos.OSVersionShort(); osname != "" {
			return osname
		}

		return unknown
	})
}

// setUptime fetches the uptime from Talos and sets it.
func (g *GuestInfo) setUptime() {
	g.setString(guestInfoUptime, func() string {
		return strconv.Itoa(g.talos.Uptime())
	})
}

// prefixToIAE converts a `netip.Prefix` into a govmomi `IPAddressEntry`.
// yes, there is a function `AddIP`, but it needs a `net.Addr` that is castable into `net.IPNet`
// and Talos yields `netip.Prefix`, and it is a pain to convert these.
func prefixToIAE(p netip.Prefix) toolbox.IPAddressEntry {
	kind := ipAddressEntryV4

	if p.Addr().Is6() {
		kind = ipAddressEntryV6
	}

	status := iasPreferred
	e := toolbox.IPAddressEntry{
		Address: toolbox.TypedIPAddress{
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
	info := toolbox.NewGuestNicInfo()

	// fetch NIC info
	for _, talosNic := range g.talos.NetInterfaces() {
		g.logger.Debug("creating NIC entry", "name", talosNic.Name, "mac", talosNic.Mac)
		nic := toolbox.GuestNicV3{MacAddress: talosNic.Mac}

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
		info.V3.DNSConfigInfo = &toolbox.DNSConfigInfo{HostName: &hostname}
	}

	infoXDR, err := toolbox.EncodeXDR(info)
	if err != nil {
		g.logger.Error("error encoding NIC info to XDR", "err", err)

		return
	}

	g.logger.Debug("setting info about nics", "len", len(info.V3.Nics))

	g.setGuestInfo(guestInfoIPAddressV3, infoXDR)
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
	g.service.AddCapability(fmt.Sprintf("SetGuestInfo  %d %d", guestInfoUptime, g.talos.Uptime()))
}
