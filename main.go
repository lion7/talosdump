package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/resource/meta"
	"github.com/cosi-project/runtime/pkg/resource/protobuf"
	"github.com/hashicorp/go-multierror"
	"github.com/lion7/extcap"
	pcap "github.com/packetcap/go-pcap/filter"
	"github.com/siderolabs/talos/cmd/talosctl/cmd/talos"
	"github.com/siderolabs/talos/cmd/talosctl/pkg/talos/helpers"
	"github.com/siderolabs/talos/pkg/machinery/api/machine"
	"github.com/siderolabs/talos/pkg/machinery/client"
	"github.com/siderolabs/talos/pkg/machinery/resources/cluster"
	"github.com/siderolabs/talos/pkg/machinery/resources/network"
	"google.golang.org/grpc/codes"
)

// Define all options
var (
	Promiscuous = extcap.NewConfigBoolOpt("promiscuous", "put interface into promiscuous mode")
	SnapLength  = extcap.NewConfigIntegerOpt("snaplen", "maximum packet size to capture").Default(65536)
	Duration    = extcap.NewConfigStringOpt("duration", "duration of the capture")
)

func main() {
	app := extcap.App{
		Usage:    "talosdump",
		HelpPage: "extcap binary for Talos Linux",
		Version: extcap.VersionInfo{
			Info: "0.0.1",
			Help: "https://github.com/lion7/extcap",
		},
		GetInterfaces:       getAllInterfaces,
		GetDLT:              getDLT,
		GetAllConfigOptions: getAllConfigOptions,
		GetConfigOptions:    getConfigOptions,
		VerifyCaptureFilter: verifyCaptureFilter,
		StartCapture:        startCapture,
	}

	app.Run(os.Args)
}

func getAllInterfaces() ([]extcap.CaptureInterface, error) {
	members, err := getTalosMembers()
	if err != nil {
		return nil, err
	}

	var ifaces []extcap.CaptureInterface
	for _, member := range members {
		node := member.TypedSpec().Hostname
		links, err := getTalosLinks(node)
		if err != nil {
			return nil, err
		}

		for _, link := range links {
			spec := link.TypedSpec()
			// only include physical ethernet or bridge links
			if spec.Physical() || spec.Kind == "bridge" {
				iface := extcap.CaptureInterface{
					Value:   link.Metadata().ID() + "@" + node,
					Display: "talosdump",
				}
				ifaces = append(ifaces, iface)
			}
		}
	}

	return ifaces, nil
}

func getDLT(iface string) (extcap.DLT, error) {
	linkId, node, err := splitLinkAndNode(iface)
	if err != nil {
		return extcap.DLT{}, err
	}

	link, err := getTalosLink(node, linkId)
	if err != nil {
		return extcap.DLT{}, err
	}

	if !link.TypedSpec().Physical() {
		return extcap.DLT{}, fmt.Errorf("only physical ethernet links are supported")
	}

	linkType := link.TypedSpec().Type
	dlt := extcap.DLT{
		Number:  int(linkType),
		Name:    linkType.String(),
		Display: iface,
	}

	return dlt, nil
}

func getConfigOptions(iface string) ([]extcap.ConfigOption, error) {
	return getAllConfigOptions(), nil
}

func getAllConfigOptions() []extcap.ConfigOption {
	opts := []extcap.ConfigOption{
		Promiscuous,
		SnapLength,
		Duration,
	}
	return opts
}

func verifyCaptureFilter(filter string) error {
	_, err := compileTcpdumpFilterToBpfFilter(filter)
	return err
}

// Most of this code is copied from / inspired by
// https://github.com/siderolabs/talos/blob/6d71bb8df29840ee7422d4462498b3dab551c981/cmd/talosctl/cmd/talos/pcap.go
func startCapture(iface string, pipe io.WriteCloser, filter string, opts map[string]interface{}) error {
	//goland:noinspection GoUnhandledErrorResult
	defer pipe.Close()

	// derive the linkId and node from the interface name
	linkId, node, err := splitLinkAndNode(iface)
	if err != nil {
		return err
	}

	// compile the provided filter (Wireshark uses the tcpdump format) to a BPF filter
	bpfFilter, err := compileTcpdumpFilterToBpfFilter(filter)
	if err != nil {
		return err
	}

	// handle input parameters
	promiscuous := false
	promiscuousOpt, ok := opts["promiscuous"]
	if ok {
		promiscuous = promiscuousOpt.(bool)
	}

	snapLen := 65536
	snapLenOpt, ok := opts["snaplen"]
	if ok {
		snapLen = snapLenOpt.(int)
	}

	var duration time.Duration
	durationOpt, ok := opts["duration"]
	if ok {
		var err error
		duration, err = time.ParseDuration(durationOpt.(string))
		if err != nil {
			return err
		}
	}

	// temporarily point stderr to /dev/null, because Talos will write to it on SIGTERM and Wireshark does not like it
	stderr := os.Stderr
	defer func() {
		os.Stderr = stderr
	}()
	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, os.ModeDevice)
	if err != nil {
		return err
	}
	os.Stderr = devNull

	// start the actual capture
	return talos.WithClientNoNodes(func(ctx context.Context, c *client.Client) error {
		// make sure we only capture on the selected node
		ctx = client.WithNodes(ctx, node)

		// set the duration as a timeout if provided
		if duration > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, duration)
			defer cancel()
		}

		// create the packet capture request
		req := machine.PacketCaptureRequest{
			Interface:   linkId,
			Promiscuous: promiscuous,
			SnapLen:     uint32(snapLen),
			BpfFilter:   bpfFilter,
		}

		// start capturing packets
		r, err := c.PacketCapture(ctx, &req)
		if err != nil {
			return fmt.Errorf("error copying: %w", err)
		}

		_, err = io.Copy(pipe, r)

		if errors.Is(err, io.EOF) || client.StatusCode(err) == codes.DeadlineExceeded {
			err = nil
		}

		return err
	})
}

func splitLinkAndNode(s string) (string, string, error) {
	if !strings.Contains(s, "@") {
		return "", "", fmt.Errorf("provided interface is not in the format 'link@node': %s", s)
	}
	split := strings.SplitN(s, "@", 2)
	return split[0], split[1], nil
}

func getTalosLink(node string, iface string) (*network.LinkStatus, error) {
	resources, err := getTalosResources(node, network.LinkStatusType, iface)
	if err != nil {
		return nil, err
	}
	if len(resources) == 0 {
		return nil, fmt.Errorf("no link found with id %s", iface)
	}
	if len(resources) > 1 {
		return nil, fmt.Errorf("multiple links found with id %s", iface)
	}
	link, ok := resources[0].(*network.LinkStatus)
	if ok {
		return link, nil
	}
	return nil, fmt.Errorf("failed to get link with id %s", iface)
}

func getTalosLinks(node string) ([]*network.LinkStatus, error) {
	var result []*network.LinkStatus
	resources, err := getTalosResources(node, network.LinkStatusType, "")
	if err != nil {
		return nil, err
	}
	for _, r := range resources {
		s, ok := r.(*network.LinkStatus)
		if ok {
			result = append(result, s)
		}
	}
	return result, nil
}

func getTalosMembers() ([]*cluster.Member, error) {
	var result []*cluster.Member
	resources, err := getTalosResources("", cluster.MemberType, "")
	if err != nil {
		return nil, err
	}
	for _, r := range resources {
		s, ok := r.(*cluster.Member)
		if ok {
			result = append(result, s)
		}
	}
	return result, nil
}

func getTalosResources(node string, resourceType resource.Type, resourceID string) ([]resource.Resource, error) {
	var result []resource.Resource
	err := talos.WithClient(func(ctx context.Context, c *client.Client) error {
		if node != "" {
			ctx = client.WithNodes(ctx, node)
		}

		var multiErr *multierror.Error
		callbackRD := func(definition *meta.ResourceDefinition) error {
			return nil
		}
		callbackResource := func(parentCtx context.Context, hostname string, r resource.Resource, callError error) error {
			if callError != nil {
				multiErr = multierror.Append(multiErr, callError)
				return nil
			}

			protoResource, ok := r.(*protobuf.Resource)
			if ok {
				var err error
				r, err = protobuf.UnmarshalResource(protoResource)
				if err != nil {
					multiErr = multierror.Append(multiErr, err)
					return nil
				}
			}

			result = append(result, r)
			return nil
		}

		err := helpers.ForEachResource(ctx, c, callbackRD, callbackResource, "", resourceType, resourceID)
		if err != nil {
			return err
		}

		return multiErr.ErrorOrNil()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func compileTcpdumpFilterToBpfFilter(filter string) ([]*machine.BPFInstruction, error) {
	if filter == "" {
		return nil, nil
	}

	expr := pcap.NewExpression(filter)
	if expr == nil {
		return nil, fmt.Errorf("failed to create expression for filter '%s'", filter)
	}

	compiled := expr.Compile()
	if compiled == nil {
		return nil, fmt.Errorf("failed to compile expression for filter '%s'", filter)
	}

	instructions, err := compiled.Compile()
	if err != nil {
		return nil, fmt.Errorf("failed compiling BPF filter '%s': %w", filter, err)
	}
	if instructions == nil {
		return nil, nil
	}

	var result []*machine.BPFInstruction
	for _, ins := range instructions {
		raw, err := ins.Assemble()
		if err != nil {
			return nil, fmt.Errorf("failed assembling BPF instruction: %w", err)
		}

		result = append(result, &machine.BPFInstruction{
			Op: uint32(raw.Op),
			Jt: uint32(raw.Jt),
			Jf: uint32(raw.Jf),
			K:  raw.K,
		})
	}

	return result, nil
}
