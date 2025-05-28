// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

// Package nicinfo holds the structs to model NIC info in the way ESX expects it, including the XDR encoding.
// It has been adapted from govmomi's toolbox, since that code does not compile on ARM64 due to its dependencies on vmw-guestinfo/bdoor.
package nicinfo

import (
	"bytes"

	xdr "github.com/rasky/go-xdr/xdr2"
)

// TypedIPAddress models an IP address and a type (family).
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type TypedIPAddress struct {
	Type    int32
	Address []byte
}

// IPAddressEntry models an IP address entry.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type IPAddressEntry struct {
	Address      TypedIPAddress
	PrefixLength uint32
	Origin       *int32 `xdr:"optional"`
	Status       *int32 `xdr:"optional"`
}

// InetCidrRouteEntry models a route entry using CIDR.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type InetCidrRouteEntry struct {
	Dest         TypedIPAddress
	PrefixLength uint32
	NextHop      *TypedIPAddress `xdr:"optional"`
	IfIndex      uint32
	Type         int32
	Metric       uint32
}

// DNSConfigInfo models DNS configuration.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type DNSConfigInfo struct {
	HostName   *string `xdr:"optional"`
	DomainName *string `xdr:"optional"`
	Servers    []TypedIPAddress
	Search     *string `xdr:"optional"`
}

// WinsConfigInfo models WINS configuration.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type WinsConfigInfo struct {
	Primary   TypedIPAddress
	Secondary TypedIPAddress
}

// DhcpConfigInfo models DHCP configuration.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type DhcpConfigInfo struct {
	Enabled  bool
	Settings string
}

// GuestNicV3 models all configuration of a guest NIC.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type GuestNicV3 struct {
	MacAddress       string
	IPs              []IPAddressEntry
	DNSConfigInfo    *DNSConfigInfo  `xdr:"optional"`
	WinsConfigInfo   *WinsConfigInfo `xdr:"optional"`
	DhcpConfigInfov4 *DhcpConfigInfo `xdr:"optional"`
	DhcpConfigInfov6 *DhcpConfigInfo `xdr:"optional"`
}

// V3 models a NIC.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type V3 struct {
	Nics             []GuestNicV3
	Routes           []InetCidrRouteEntry
	DNSConfigInfo    *DNSConfigInfo  `xdr:"optional"`
	WinsConfigInfo   *WinsConfigInfo `xdr:"optional"`
	DhcpConfigInfov4 *DhcpConfigInfo `xdr:"optional"`
	DhcpConfigInfov6 *DhcpConfigInfo `xdr:"optional"`
}

// GuestNicInfo models guest NIC info.
//
//nolint:govet // VMWare expects the fields in a very specific order. It will break when you satisfy `fieldalignment`
type GuestNicInfo struct {
	Version int32
	V3      *V3 `xdr:"optional"`
}

// New returns a new, empty GuestNicInfo object in version 3.
func New() *GuestNicInfo {
	return &GuestNicInfo{
		Version: 3,
		V3:      &V3{},
	}
}

// EncodeXDR encodes something into XDR encoding.
func EncodeXDR(val any) ([]byte, error) {
	var buf bytes.Buffer

	_, err := xdr.Marshal(&buf, val)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
