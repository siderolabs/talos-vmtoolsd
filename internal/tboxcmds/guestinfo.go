package tboxcmds

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	xdr "github.com/stellar/go-xdr/xdr3"

	"github.com/siderolabs/talos-vmtoolsd/internal/nanotoolbox"
)

const (
	_ = iota
	// GuestInfoDNSName is the guest info kind for the DNS name.
	GuestInfoDNSName
	_ // IP v1
	_ // free disk space
	_ // build number
	// GuestInfoOSNameFull is the guest info kind for the full OS name.
	GuestInfoOSNameFull
	// GuestInfoOSName is the guest info kind for the OS name.
	GuestInfoOSName
	// GuestInfoUptime is the guest uptime in 100s of seconds.
	GuestInfoUptime
	_ // memory
	_ // IP v2
	// GuestInfoIPAddressV3 is the guest info kind for the IP address.
	GuestInfoIPAddressV3
	_ // OS detailed
)

const (
	unknownIP = "unknown"
	maxNICs   = 16
)

// NetInterface represents a network interface.
type NetInterface struct {
	Name  string
	MAC   string // xx:xx:xx:xx:xx:xx
	Addrs []netip.Prefix
}

// NicDelegate is the interface that must be implemented by the delegate.
type NicDelegate interface {
	NetInterfaces() []NetInterface
	Hostname() string
	OSVersion() string
	OSVersionShort() string
}

// GuestInfoCommands provides a set of commands for the vmx.
type GuestInfoCommands struct {
	log      logrus.FieldLogger
	out      *nanotoolbox.ChannelOut
	delegate NicDelegate
}

// PrimaryIP returns the primary IP address.
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

	return addrs[0].String()
}

// GuestNicInfo represents the guest NIC info.
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

// SendGuestInfo sends the guest info.
func (cmd *GuestInfoCommands) SendGuestInfo(kind int, buf []byte) {
	// NB: intentionally using two spaces as separator to match open-vm-tools
	msg := append([]byte(fmt.Sprintf("SetGuestInfo  %d ", kind)), buf...)
	if _, err := cmd.out.Request(msg); err != nil {
		cmd.log.WithError(err).WithField("guest_info_kind", kind).Error("error sending guest info")
	}
}

// SendGuestInfoString sends the guest info string.
func (cmd *GuestInfoCommands) SendGuestInfoString(kind int, str string) {
	cmd.SendGuestInfo(kind, []byte(str))
}

// SendGuestInfoXDR sends the guest info XDR.
func (cmd *GuestInfoCommands) SendGuestInfoXDR(kind int, v interface{}) {
	var buf bytes.Buffer

	_, err := xdr.Marshal(&buf, v)
	if err != nil {
		cmd.log.WithError(err).WithField("guest_info_kind", kind).Error("error encoding guest info")

		return
	}

	cmd.SendGuestInfo(kind, buf.Bytes())
}

// SendGuestInfoDNSName sends the guest info DNS name.
func (cmd *GuestInfoCommands) SendGuestInfoDNSName() {
	if hostname := cmd.delegate.Hostname(); hostname != "" {
		cmd.log.Debugf("sending hostname: %v", hostname)
		cmd.SendGuestInfoString(GuestInfoDNSName, hostname)
	}
}

// SendGuestInfoOSNameFull sends the guest info OS full name.
func (cmd *GuestInfoCommands) SendGuestInfoOSNameFull() {
	if name := cmd.delegate.OSVersion(); name != "" {
		cmd.log.Debugf("sending OS full name: %v", name)
		cmd.SendGuestInfoString(GuestInfoOSNameFull, name)
	}
}

// SendGuestInfoOSName sends the guest info OS name.
func (cmd *GuestInfoCommands) SendGuestInfoOSName() {
	if name := cmd.delegate.OSVersionShort(); name != "" {
		cmd.log.Debugf("sending OS short name: %v", name)
		cmd.SendGuestInfoString(GuestInfoOSName, name)
	}
}

// GuestUptime represents the system uptime.
func (cmd *GuestInfoCommands) GuestUptime() int64 {
	u, err := os.ReadFile("/proc/uptime")
	if err != nil {
		cmd.log.WithError(err).Error("error getting uptime")

		return -1
	}

	field := bytes.Fields(u)[0]

	uptime, err := strconv.ParseFloat(string(field), 64)
	if err != nil {
		cmd.log.WithError(err).Error("error getting uptime")

		return -1
	}

	return int64(uptime * 100)
}

// SendGuestInfoUptime sends the guest uptime.
func (cmd *GuestInfoCommands) SendGuestInfoUptime() {
	uptime := cmd.GuestUptime()
	cmd.log.Debugf("sending uptime: %v", uptime)
	cmd.SendGuestInfoString(GuestInfoUptime, fmt.Sprintf("%d", uptime))
}

// SendGuestInfoNIC sends the guest info NIC.
func (cmd *GuestInfoCommands) SendGuestInfoNIC() {
	cmd.SendGuestInfoXDR(GuestInfoIPAddressV3, cmd.GuestNicInfo())
}

// BroadcastIPOptionHandler handles the broadcast IP option.
func (cmd *GuestInfoCommands) BroadcastIPOptionHandler(string, string) {
	msg := fmt.Sprintf("info-set guestinfo.ip %s", cmd.PrimaryIP())
	if _, err := cmd.out.Request([]byte(msg)); err != nil {
		cmd.log.WithError(err).Error("error sending IP message")
	}

	cmd.SendGuestInfoNIC()
}

// PushGuestInfo pushes the guest info.
func (cmd *GuestInfoCommands) PushGuestInfo() {
	cmd.SendGuestInfoDNSName()
	cmd.SendGuestInfoOSNameFull()
	cmd.SendGuestInfoOSName()
	cmd.SendGuestInfoUptime()
	cmd.SendGuestInfoNIC()
}

// RegisterGuestInfoCommands registers the guest info commands.
func RegisterGuestInfoCommands(svc *nanotoolbox.Service, delegate NicDelegate) {
	cmd := &GuestInfoCommands{
		log:      svc.Log.WithField("module", "tboxcmds"),
		out:      svc.Out,
		delegate: delegate,
	}
	svc.RegisterResetHandler(cmd.PushGuestInfo)
	svc.RegisterOptionHandler("broadcastIP", cmd.BroadcastIPOptionHandler)

	// As stated in guestInfoServer.c, VMX expects uptime information in response
	// to the capabilities request.
	svc.AddCapability(fmt.Sprintf("SetGuestInfo  %d %d", GuestInfoUptime, cmd.GuestUptime()))
}
