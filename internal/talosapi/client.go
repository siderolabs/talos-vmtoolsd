// Package talosapi represents the Talos API client.
package talosapi

import (
	"context"
	"fmt"

	"github.com/cosi-project/runtime/pkg/safe"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/siderolabs/talos/pkg/grpc/middleware/authz"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	talosclient "github.com/siderolabs/talos/pkg/machinery/client"
	talosconfig "github.com/siderolabs/talos/pkg/machinery/client/config"
	talosconstants "github.com/siderolabs/talos/pkg/machinery/constants"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	talosrole "github.com/siderolabs/talos/pkg/machinery/role"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/siderolabs/talos-vmtoolsd/internal/tboxcmds"
)

// LocalClient represents the Talos API client.
type LocalClient struct {
	ctx context.Context //nolint:containedctx
	log logrus.FieldLogger
	api *talosclient.Client
}

// Close closes the client.
func (c *LocalClient) Close() error {
	return c.api.Close()
}

func (c *LocalClient) connectToApid(configPath string, k8sHost string) (*talosclient.Client, error) {
	cfg, err := talosconfig.Open(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %q: %w", configPath, err)
	}

	opts := []talosclient.OptionFunc{
		talosclient.WithConfig(cfg),
		talosclient.WithEndpoints(k8sHost),
	}

	api, err := talosclient.New(c.ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to construct client: %w", err)
	}

	return api, nil
}

func (c *LocalClient) connectToMachined() (*talosclient.Client, error) {
	opts := []talosclient.OptionFunc{
		talosclient.WithUnixSocket(talosconstants.MachineSocketPath),
		talosclient.WithGRPCDialOptions(grpc.WithTransportCredentials(insecure.NewCredentials())),
	}
	md := metadata.New(nil)
	authz.SetMetadata(md, talosrole.MakeSet(talosrole.Admin))
	c.ctx = metadata.NewOutgoingContext(c.ctx, md)

	api, err := talosclient.New(c.ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to construct client: %w", err)
	}

	return api, nil
}

// Shutdown shuts down the machine.
func (c *LocalClient) Shutdown() error {
	return c.api.Shutdown(c.ctx)
}

// Reboot reboots the machine.
func (c *LocalClient) Reboot() error {
	return c.api.Reboot(c.ctx)
}

func (c *LocalClient) osVersionInfo() (*machine.VersionInfo, error) {
	resp, err := c.api.Version(c.ctx)
	if err != nil || len(resp.Messages) == 0 {
		return nil, err
	}

	return resp.Messages[0].Version, nil
}

// OSVersion returns the OS version.
func (c *LocalClient) OSVersion() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.WithError(err).Error("error retrieving OS version information")

		return "Talos"
	}

	return fmt.Sprintf("Talos %s-%s", v.Tag, v.Sha)
}

// OSVersionShort returns the short OS version.
func (c *LocalClient) OSVersionShort() string {
	v, err := c.osVersionInfo()
	if err != nil {
		c.log.WithError(err).Error("error retrieving OS version information")

		return "Talos"
	}

	return fmt.Sprintf("Talos %s", v.Tag)
}

// Hostname returns the hostname.
func (c *LocalClient) Hostname() string {
	resp, err := c.api.MachineClient.Hostname(c.ctx, &empty.Empty{})
	if err != nil || len(resp.Messages) == 0 {
		c.log.WithError(err).Error("error retrieving hostname")

		return ""
	}

	return resp.Messages[0].Hostname
}

// NetInterfaces returns the network interfaces.
func (c *LocalClient) NetInterfaces() (result []tboxcmds.NetInterface) {
	addrMap := make(map[string][]*network.AddressStatusSpec)

	networkAddresses, err := safe.StateListAll[*network.AddressStatus](c.ctx, c.api.COSI)
	if err != nil {
		c.log.WithError(err).Error("error listing address status resources")

		return nil
	}

	iter := networkAddresses.Iterator()

	for iter.Next() {
		linkName := iter.Value().TypedSpec().LinkName
		addrMap[linkName] = append(addrMap[linkName], iter.Value().TypedSpec())
	}

	linkStatuses, err := safe.StateListAll[*network.LinkStatus](c.ctx, c.api.COSI)
	if err != nil {
		c.log.WithError(err).Error("error listing link status resources")

		return nil
	}

	linksIter := linkStatuses.Iterator()

	for linksIter.Next() {
		link := linksIter.Value().TypedSpec()

		if !link.Physical() {
			continue
		}

		intf := tboxcmds.NetInterface{
			Name: linksIter.Value().Metadata().ID(),
			MAC:  link.HardwareAddr.String(),
		}

		for _, addr := range addrMap[intf.Name] {
			intf.Addrs = append(intf.Addrs, addr.Address)
		}

		result = append(result, intf)
	}

	return result
}

// NewLocalClient creates a new Talos API client.
func NewLocalClient(ctx context.Context, log logrus.FieldLogger, configPath string, k8sHost string) (*LocalClient, error) {
	var err error

	c := &LocalClient{
		ctx: ctx,
		log: log.WithField("module", "talosapi"),
	}

	c.api, err = c.connectToApid(configPath, k8sHost)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to apid: %w", err)
	}

	return c, nil
}

// NewLocalSocketClient creates a new Talos API client using a local socket.
func NewLocalSocketClient(ctx context.Context, log logrus.FieldLogger) (*LocalClient, error) {
	var err error

	c := &LocalClient{
		ctx: ctx,
		log: log.WithField("module", "talosapi"),
	}

	c.api, err = c.connectToMachined()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to machined: %w", err)
	}

	return c, nil
}
