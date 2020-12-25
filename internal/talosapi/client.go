package talosapi

import (
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/mologie/talos-vmtoolsd/internal/tboxcmds"
	"github.com/talos-systems/talos/pkg/machinery/api/machine"
	talosclient "github.com/talos-systems/talos/pkg/machinery/client"
	talosconfig "github.com/talos-systems/talos/pkg/machinery/client/config"
	"log"
	"net"
	"regexp"
)

type LocalClient struct {
	ctx        context.Context
	log        *log.Logger
	configPath string
	k8sHost    string
	api        *talosclient.Client
}

var PhysIntfRegex = regexp.MustCompile("^eth[0-9]+$")

func (c *LocalClient) connect() (*talosclient.Client, error) {
	cfg, err := talosconfig.Open(c.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %w", c.configPath, err)
	}
	opts := []talosclient.OptionFunc{
		talosclient.WithConfig(cfg),
		talosclient.WithEndpoints(c.k8sHost),
	}
	api, err := talosclient.New(c.ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to construct client: %w", err)
	}
	return api, nil
}

func (c *LocalClient) Shutdown() error {
	return c.api.Shutdown(c.ctx)
}

func (c *LocalClient) Reboot() error {
	return c.api.Reboot(c.ctx)
}

func (c *LocalClient) osVersionInfo() (*machine.VersionInfo, error) {
	resp, err := c.api.Version(c.ctx)
	if err != nil || len(resp.Messages) == 0 {
		return nil, err
	} else {
		return resp.Messages[0].Version, nil
	}
}

func (c *LocalClient) OSVersion() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.Printf("[talosapi] error retrieving OS version information: %v", err)
		return "Talos"
	}
	return fmt.Sprintf("Talos %s-%s", v.Tag, v.Sha)
}

func (c *LocalClient) OSVersionShort() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.Printf("[talosapi] error retrieving OS version information: %v", err)
		return "Talos"
	}
	return fmt.Sprintf("Talos %s", v.Tag)
}

func (c *LocalClient) Hostname() string {
	resp, err := c.api.MachineClient.Hostname(c.ctx, &empty.Empty{})
	if err != nil || len(resp.Messages) == 0 {
		c.log.Printf("[talosapi] error retrieving hostname: %v", err)
		return ""
	} else {
		return resp.Messages[0].Hostname
	}
}

func (c *LocalClient) NetInterfaces() (result []tboxcmds.NetInterface) {
	resp, err := c.api.Interfaces(c.ctx)
	if err != nil || len(resp.Messages) == 0 {
		c.log.Printf("[talosapi] error retrieving network interface list: %v", err)
		return nil
	}
	ifs := resp.Messages[0].Interfaces
	for _, nic := range ifs {
		if PhysIntfRegex.MatchString(nic.Name) {
			wrappedIf := tboxcmds.NetInterface{
				Name: nic.Name,
				MAC:  nic.Hardwareaddr,
			}
			for _, ip := range nic.Ipaddress {
				ip, cidr, err := net.ParseCIDR(ip)
				if err != nil {
					continue
				}
				cidr.IP = ip
				wrappedIf.Addrs = append(wrappedIf.Addrs, cidr)
			}
			result = append(result, wrappedIf)
		}
	}
	return
}

func NewLocalClient(log *log.Logger, configPath string, k8sHost string) (*LocalClient, error) {
	var err error
	c := &LocalClient{ctx: context.Background(), log: log, configPath: configPath, k8sHost: k8sHost}
	c.api, err = c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to apid: %v", err)
	}
	return c, nil
}
