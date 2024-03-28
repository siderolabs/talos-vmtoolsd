// This file was copied from govmomi/toolbox's guest_info.go.
// The original copyright notice follows.

/*
Copyright (c) 2017 VMware, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Defs from: open-vm-tools/lib/guestRpc/nicinfo.x

package tboxcmds

import "net/netip"

// TypedIPAddress represents an IP address with a type.
type TypedIPAddress struct { //nolint:govet
	Type    int32
	Address []byte
}

// IPAddressEntry represents an IP address with prefix length, origin, and status.
type IPAddressEntry struct { //nolint:govet
	Address      TypedIPAddress
	PrefixLength uint32
	Origin       *int32 `xdr:"optional"`
	Status       *int32 `xdr:"optional"`
}

// InetCidrRouteEntry represents a route entry.
type InetCidrRouteEntry struct { //nolint:govet
	Dest         TypedIPAddress
	PrefixLength uint32
	NextHop      *TypedIPAddress `xdr:"optional"`
	IfIndex      uint32
	Type         int32
	Metric       uint32
}

// DNSConfigInfo represents DNS configuration.
type DNSConfigInfo struct { //nolint:govet
	HostName   *string `xdr:"optional"`
	DomainName *string `xdr:"optional"`
	Servers    []TypedIPAddress
	Search     *string `xdr:"optional"`
}

// WinsConfigInfo represents WINS configuration.
type WinsConfigInfo struct {
	Primary   TypedIPAddress
	Secondary TypedIPAddress
}

// DhcpConfigInfo represents DHCP configuration.
type DhcpConfigInfo struct { //nolint:govet
	Enabled  bool
	Settings string
}

// GuestNicV3 represents NIC information.
type GuestNicV3 struct { //nolint:govet
	MacAddress       string
	IPs              []IPAddressEntry
	DNSConfigInfo    *DNSConfigInfo  `xdr:"optional"`
	WinsConfigInfo   *WinsConfigInfo `xdr:"optional"`
	DhcpConfigInfov4 *DhcpConfigInfo `xdr:"optional"`
	DhcpConfigInfov6 *DhcpConfigInfo `xdr:"optional"`
}

// GuestNicInfo represents NIC information.
type GuestNicInfo struct { //nolint:govet
	Version int32
	V3      *NicInfoV3 `xdr:"optional"`
}

// AddIP adds an IP address to the NIC.
func (nic *GuestNicV3) AddIP(prefix netip.Prefix) {
	addr := prefix.Addr()
	kind := int32(1) // IAT_IPV4

	if addr.Is6() {
		kind = 2 // IAT_IPV6
	} else if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4()) // convert to 4-byte representation
	}

	// nicinfo.x defines enum IpAddressStatus, but vmtoolsd only uses IAS_PREFERRED
	var status int32 = 1 // IAS_PREFERRED

	e := IPAddressEntry{
		Address: TypedIPAddress{
			Type:    kind,
			Address: addr.AsSlice(),
		},
		PrefixLength: uint32(prefix.Bits()),
		Status:       &status,
	}

	nic.IPs = append(nic.IPs, e)
}

// NicInfoV3 contains NIC information.
type NicInfoV3 struct { //nolint:govet
	Nics             []GuestNicV3
	Routes           []InetCidrRouteEntry
	DNSConfigInfo    *DNSConfigInfo  `xdr:"optional"`
	WinsConfigInfo   *WinsConfigInfo `xdr:"optional"`
	DhcpConfigInfov4 *DhcpConfigInfo `xdr:"optional"`
	DhcpConfigInfov6 *DhcpConfigInfo `xdr:"optional"`
}

// NewGuestNicInfo creates a new GuestNicInfo.
func NewGuestNicInfo() *GuestNicInfo {
	return &GuestNicInfo{
		Version: 3,
		V3:      &NicInfoV3{},
	}
}
