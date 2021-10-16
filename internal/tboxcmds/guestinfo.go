package tboxcmds

import (
	"bytes"
	"fmt"
	"github.com/mologie/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/sirupsen/logrus"
	xdr "github.com/stellar/go-xdr/xdr3"
	"net"
)

const (
	_ = iota
	GuestInfoDNSName
	_ // IP v1
	_ // free disk space
	_ // build number
	GuestInfoOSNameFull
	GuestInfoOSName
	_ // uptime
	_ // memory
	_ // IP v2
	GuestInfoIPAddressV3
	_ // OS detailed
)

const unknownIP = "unknown"
const maxNICs = 16

type NetInterface struct {
	Name  string
	MAC   string // xx:xx:xx:xx:xx:xx
	Addrs []net.Addr
}

type NicDelegate interface {
	NetInterfaces() []NetInterface
	Hostname() string
	OSVersion() string
	OSVersionShort() string
}

type GuestInfoCommands struct {
	log      logrus.FieldLogger
	out      *nanotoolbox.ChannelOut
	delegate NicDelegate
}

func (cmd *GuestInfoCommands) PrimaryIP() string {
	ifs := cmd.delegate.NetInterfaces()
	if len(ifs) < 1 {
		cmd.log.Warn("not sending primary IP: no interfaces received from upstream")
		return unknownIP
	}
	addrs := ifs[0].Addrs
	if len(addrs) < 1 {
		cmd.log.Warn("not sending primary IP: first upstream adapter has no addresses")
		return unknownIP
	}
	ipnet, ok := addrs[0].(*net.IPNet)
	if !ok {
		cmd.log.Warn("not sending primary IP: expected first upstream IP with type net.IPNet")
		return unknownIP
	}
	return ipnet.IP.String()
}

func (cmd *GuestInfoCommands) GuestNicInfo() *GuestNicInfo {
	// NB: this is polled by vSphere roughly every 30s
	info := NewGuestNicInfo()
	ifs := cmd.delegate.NetInterfaces()
	for _, nic := range ifs {
		nicDesc := GuestNicV3{MacAddress: nic.MAC}
		for _, addr := range nic.Addrs {
			nicDesc.AddIP(addr)
			cmd.log.Debugf("GuestNicInfo: adding name=%v mac=%v ip=%v", nic.Name, nic.MAC, addr)
		}
		info.V3.Nics = append(info.V3.Nics, nicDesc)
		if len(info.V3.Nics) >= maxNICs {
			cmd.log.Debugf("GuestNicInfo: truncating NIC list to %v NICs", maxNICs)
			break
		}
	}
	if hostname := cmd.delegate.Hostname(); hostname != "" {
		info.V3.DNSConfigInfo = &DNSConfigInfo{HostName: &hostname}
	}
	return info
}

func (cmd *GuestInfoCommands) SendGuestInfo(kind int, buf []byte) {
	// NB: intentionally using two spaces as separator to match open-vm-tools
	msg := append([]byte(fmt.Sprintf("SetGuestInfo  %d ", kind)), buf...)
	if _, err := cmd.out.Request(msg); err != nil {
		cmd.log.WithError(err).WithField("guest_info_kind", kind).Error("error sending guest info")
	}
}

func (cmd *GuestInfoCommands) SendGuestInfoString(kind int, str string) {
	cmd.SendGuestInfo(kind, []byte(str))
}

func (cmd *GuestInfoCommands) SendGuestInfoXDR(kind int, v interface{}) {
	var buf bytes.Buffer
	_, err := xdr.Marshal(&buf, v)
	if err != nil {
		cmd.log.WithError(err).WithField("guest_info_kind", kind).Error("error encoding guest info")
		return
	}
	cmd.SendGuestInfo(kind, buf.Bytes())
}

func (cmd *GuestInfoCommands) SendGuestInfoDNSName() {
	if hostname := cmd.delegate.Hostname(); hostname != "" {
		cmd.log.Debugf("sending hostname: %v", hostname)
		cmd.SendGuestInfoString(GuestInfoDNSName, hostname)
	}
}

func (cmd *GuestInfoCommands) SendGuestInfoOSNameFull() {
	if name := cmd.delegate.OSVersion(); name != "" {
		cmd.log.Debugf("sending OS full name: %v", name)
		cmd.SendGuestInfoString(GuestInfoOSNameFull, name)
	}
}

func (cmd *GuestInfoCommands) SendGuestInfoOSName() {
	if name := cmd.delegate.OSVersionShort(); name != "" {
		cmd.log.Debugf("sending OS short name: %v", name)
		cmd.SendGuestInfoString(GuestInfoOSName, name)
	}
}

func (cmd *GuestInfoCommands) SendGuestInfoNIC() {
	cmd.SendGuestInfoXDR(GuestInfoIPAddressV3, cmd.GuestNicInfo())
}

func (cmd *GuestInfoCommands) BroadcastIPOptionHandler(string, string) {
	msg := fmt.Sprintf("info-set guestinfo.ip %s", cmd.PrimaryIP())
	if _, err := cmd.out.Request([]byte(msg)); err != nil {
		cmd.log.WithError(err).Error("error sending IP message")
	}
	cmd.SendGuestInfoNIC()
}

func (cmd *GuestInfoCommands) PushGuestInfo() {
	cmd.SendGuestInfoDNSName()
	cmd.SendGuestInfoOSNameFull()
	cmd.SendGuestInfoOSName()
	cmd.SendGuestInfoNIC()
}

func RegisterGuestInfoCommands(svc *nanotoolbox.Service, delegate NicDelegate) {
	cmd := &GuestInfoCommands{
		log:      svc.Log.WithField("module", "tboxcmds"),
		out:      svc.Out,
		delegate: delegate,
	}
	svc.RegisterResetHandler(cmd.PushGuestInfo)
	svc.RegisterOptionHandler("broadcastIP", cmd.BroadcastIPOptionHandler)
}
