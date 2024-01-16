package talosapi

import (
	"context"
	"fmt"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/siderolabs/talos-vmtoolsd/internal/tboxcmds"
	"github.com/sirupsen/logrus"
	"github.com/talos-systems/talos/pkg/machinery/api/machine"
	resourceapi "github.com/talos-systems/talos/pkg/machinery/api/resource"
	talosclient "github.com/talos-systems/talos/pkg/machinery/client"
	talosconfig "github.com/talos-systems/talos/pkg/machinery/client/config"
	"github.com/talos-systems/talos/pkg/resources/network"
	"gopkg.in/yaml.v2"
	"inet.af/netaddr"
	"io"
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
	// TODO: There does not appear proper built-in unmarshalling to API objects such as
	//   network.AddressStatus yet. All we get back is YAML. Additionally Talos' nethelpers
	//   supports marshalling only which blocks reusing existing object definitions for decoding.
	//   Meh.

	type AddressStatusSpec struct {
		Address  netaddr.IPPrefix `yaml:"address"`
		LinkName string           `yaml:"linkName"`
	}

	type LinkStatusSpec struct {
		Type         string `yaml:"type"`
		HardwareAddr string `yaml:"hardwareAddr"`
		Kind         string `yaml:"kind"`
	}

	addrMap := make(map[string][]AddressStatusSpec)
	addrClient, err := c.api.ResourceClient.List(c.ctx, &resourceapi.ListRequest{
		Namespace: network.NamespaceName,
		Type:      network.AddressStatusType,
	})
	if err != nil {
		c.log.WithError(err).Error("error listing address status resources")
		return nil
	}

	for {
		msg, err := addrClient.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			c.log.WithError(err).Error("error receiving address status resource")
			return nil
		}
		if msg.Resource == nil {
			continue
		}
		var spec AddressStatusSpec
		if err := yaml.Unmarshal(msg.Resource.Spec.Yaml, &spec); err != nil {
			c.log.WithError(err).Error("error decoding address status resource")
			continue
		}
		addrMap[spec.LinkName] = append(addrMap[spec.LinkName], spec)
	}

	linkClient, err := c.api.ResourceClient.List(c.ctx, &resourceapi.ListRequest{
		Namespace: network.NamespaceName,
		Type:      network.LinkStatusType,
	})
	if err != nil {
		c.log.WithError(err).Error("error listing link status resources")
		return nil
	}

	for {
		msg, err := linkClient.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			c.log.WithError(err).Error("error receiving link status resource")
			return nil
		}
		if msg.Resource == nil {
			continue
		}

		var spec LinkStatusSpec
		if err := yaml.Unmarshal(msg.Resource.Spec.Yaml, &spec); err != nil {
			c.log.WithError(err).Error("error decoding link status resource")
			continue
		}

		// via: network.LinkStatus.Physical()
		if spec.Type != "ether" || spec.Kind != "" {
			continue
		}

		intf := tboxcmds.NetInterface{
			Name: msg.Resource.Metadata.Id,
			MAC:  spec.HardwareAddr,
		}

		for _, addr := range addrMap[intf.Name] {
			intf.Addrs = append(intf.Addrs, addr.Address.IPNet())
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
