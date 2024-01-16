package talosapi

import (
	"context"
	"fmt"
	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/mologie/talos-vmtoolsd/internal/tboxcmds"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	talosclient "github.com/siderolabs/talos/pkg/machinery/client"
	talosconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"github.com/sirupsen/logrus"
)

type LocalClient struct {
	ctx        context.Context
	log        logrus.FieldLogger
	configPath string
	k8sHost    string
	api        *talosclient.Client
}

func (c *LocalClient) Close() error {
	return c.api.Close()
}

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
		c.log.WithError(err).Error("error retrieving OS version information")
		return "Talos"
	}
	return fmt.Sprintf("Talos %s-%s", v.Tag, v.Sha)
}

func (c *LocalClient) OSVersionShort() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.WithError(err).Error("error retrieving OS version information")
		return "Talos"
	}
	return fmt.Sprintf("Talos %s", v.Tag)
}

func (c *LocalClient) Hostname() string {
	resp, err := c.api.MachineClient.Hostname(c.ctx, &empty.Empty{})
	if err != nil || len(resp.Messages) == 0 {
		c.log.WithError(err).Error("error retrieving hostname")
		return ""
	} else {
		return resp.Messages[0].Hostname
	}
}

func (c *LocalClient) NetInterfaces() (result []tboxcmds.NetInterface) {
	addrMap := make(map[string][]*network.AddressStatusSpec)
	addrStatusMap, err := c.api.COSI.List(c.ctx, resource.NewMetadata(
		network.NamespaceName,
		network.AddressStatusType,
		"",
		resource.VersionUndefined,
	))
	if err != nil {
		c.log.WithError(err).Error("error listing address status resources")
		return nil
	}
	for _, res := range addrStatusMap.Items {
		spec := res.(*network.AddressStatus).Spec().(*network.AddressStatusSpec)
		addrMap[spec.LinkName] = append(addrMap[spec.LinkName], spec)
	}

	linkStatusList, err := c.api.COSI.List(c.ctx, resource.NewMetadata(
		network.NamespaceName,
		network.LinkStatusType,
		"",
		resource.VersionUndefined,
	))
	if err != nil {
		c.log.WithError(err).Error("error listing link status resources")
		return nil
	}
	for _, res := range linkStatusList.Items {
		spec := res.(*network.LinkStatus).Spec().(*network.LinkStatusSpec)
		if !spec.Physical() {
			continue
		}
		intf := tboxcmds.NetInterface{
			Name: res.Metadata().ID(),
			MAC:  spec.HardwareAddr.String(),
		}
		for _, addr := range addrMap[intf.Name] {
			intf.Addrs = append(intf.Addrs, addr.Address)
		}
		result = append(result, intf)
	}

	return
}

func NewLocalClient(log logrus.FieldLogger, configPath string, k8sHost string) (*LocalClient, error) {
	var err error
	c := &LocalClient{
		ctx:        context.Background(),
		log:        log.WithField("module", "talosapi"),
		configPath: configPath,
		k8sHost:    k8sHost,
	}
	c.api, err = c.connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to apid: %v", err)
	}
	return c, nil
}
