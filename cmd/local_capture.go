package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/containerd"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

var localCaptureCmd = &cobra.Command{
	Use:   "local-capture [filter]",
	Short: "Capture packets locally on the specified interface",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runLocalCapture,
}

func init() {
	rootCmd.AddCommand(localCaptureCmd)
	captureFlags := newCaptureFlags()
	localCaptureCmd.Flags().AddFlagSet(captureFlags)
	localCaptureCmd.Flags().StringSliceP("netns", "N", []string{}, "Run the capture in the specified network namespaces")
}

func runLocalCapture(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	var filter string
	if len(args) == 1 {
		filter = args[0]
	}

	captureOpts, err := getCaptureOpts(ctx, filter, cmd.Flags())
	if err != nil {
		return err
	}

	netNamespaces, err := cmd.Flags().GetStringSlice("netns")
	if err != nil {
		return err
	}

	// Validate certain flags are only used on Linux
	if runtime.GOOS != "linux" {
		var flag string
		switch {
		case len(netNamespaces) > 0:
			flag = "--netns"
		case len(captureOpts.K8sPod) != 0:
			flag = "--k8s-pod"
		case captureOpts.K8sNamespace != "":
			flag = "--k8s-namespace"
		}
		if flag != "" {
			return fmt.Errorf("%s is only valid on Linux", flag)
		}
	}

	if len(captureOpts.K8sPod) > 1 {
		return errors.New("local-capture only supports a single pod filter")
	}
	if captureOpts.K8sNamespace != "" && len(captureOpts.K8sPod) != 0 {
		podName := captureOpts.K8sPod[0]

		containerdSock := "/run/containerd/containerd.sock"
		captureOpts.Logger.Debug("connecting to containerd", "addr", containerdSock)
		client, err := containerd.New(containerdSock)
		if err != nil {
			return fmt.Errorf("error connecting to containerd: %w", err)
		}
		defer client.Close()

		captureOpts.Logger.Debug("looking up k8s pod in containerd", "pod", podName, "namespace", captureOpts.K8sNamespace)
		pod, err := containerd.GetPod(ctx, client, podName, captureOpts.K8sNamespace)
		if err != nil {
			return fmt.Errorf("error getting pod namespace: %w", err)
		}
		if pod.Name == "" {
			return fmt.Errorf("could not find pod '%s/%s'", captureOpts.K8sNamespace, podName)
		}
		captureOpts.Logger.Debug("found pod", "pod", pod.Name, "namespace", captureOpts.K8sNamespace, "netns", pod.Netns)
		netNamespaces = append(netNamespaces, pod.Netns)
	}

	return localCapture(ctx, captureOpts.Logger, captureOpts.Interfaces, netNamespaces, captureOpts.CaptureConfig, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

// localCapture runs a packet capture and stores the output to the specified file or
// logs the packets to stdout with the configured logger if outputFile is
// empty.
// If alwaysPrint is true; it prints regardless whether outputFile is empty.
func localCapture(ctx context.Context, log *slog.Logger, ifaces []string, netNamespaces []string, conf capture.Config, outputPath string, alwaysPrint bool) error {
	var isDir bool
	if outputPath != "" {
		fi, err := os.Stat(outputPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && fi.IsDir() {
			isDir = true
		}
	}
	printPackets := outputPath == "" || alwaysPrint

	clock := clockwork.NewRealClock()

	handle, err := newLocalCaptureHandle(ctx, log, clock, ifaces, netNamespaces, conf)
	if err != nil {
		return fmt.Errorf("error creating capture: %w", err)
	}
	defer handle.Close()
	linkType := handle.LinkType()

	handler := newCommonOutputHandler(linkType, uint32(conf.Snaplen), printPackets, outputPath, isDir, conf.OutputFormat)
	defer handler.Flush()

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}

	return nil
}

type localCaptureHandle struct {
	log      *slog.Logger
	clock    clockwork.Clock
	ifaces   []string
	conf     capture.Config
	source   *localCaptureSource
	linkType layers.LinkType
}

func newLocalCaptureHandle(ctx context.Context, log *slog.Logger, clock clockwork.Clock, ifaces []string, netNamespaces []string, conf capture.Config) (*localCaptureHandle, error) {
	source, err := newLocalCaptureSource(ctx, log, netNamespaces, ifaces, conf)
	if err != nil {
		return nil, fmt.Errorf("error creating local capture source: %w", err)
	}

	linkType := source.LinkType()
	return &localCaptureHandle{
		log:      log,
		clock:    clock,
		ifaces:   ifaces,
		conf:     conf,
		source:   source,
		linkType: linkType,
	}, nil
}

func (csh *localCaptureHandle) Start(ctx context.Context, handler capture.PacketHandler) error {
	start := csh.clock.Now()
	packetsTotal := 0
	csh.log.Info("multi capture started", "interface", csh.ifaces, "snaplen", csh.conf.Snaplen, "promisc", csh.conf.Promisc, "num_packets", csh.conf.NumPackets, "duration", csh.conf.CaptureDuration)

	defer func() {
		csh.log.Info("multi capture finished", "interface", csh.ifaces, "packets", packetsTotal, "capture_duration", csh.clock.Since(start))
	}()

	packetSource := gopacket.NewPacketSource(csh.source, csh.linkType)

	for packet := range packetSource.PacketsCtx(ctx) {
		if err := handler.HandlePacket(packet); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		packetsTotal++
	}

	return nil
}

func (csh *localCaptureHandle) LinkType() layers.LinkType {
	return csh.linkType
}

func (csh *localCaptureHandle) Close() {
}

type localCaptureSource struct {
	packets chan capture.TimestampedPacket
	errs    chan error

	linkType layers.LinkType
}

func newLocalCaptureSource(ctx context.Context, log *slog.Logger, networkNamespaces []string, ifaces []string, conf capture.Config) (*localCaptureSource, error) {
	if len(networkNamespaces) == 0 {
		networkNamespaces = []string{""}
	}

	if len(ifaces) == 0 {
		ifaces = []string{""}
	}

	// forwardHandler to aggregate packets from multiple capture.Capture handles
	// into a single capture.PacketSource
	packets := make(chan capture.TimestampedPacket)
	forwardHandler := capture.PacketHandlerFunc(func(p gopacket.Packet) error {
		select {
		case packets <- &capture.GoPacketWrapper{Packet: p}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	var linkType layers.LinkType
	eg, ctx := errgroup.WithContext(ctx)

	// Initialize a capture for each netns/interface combination
	for _, netns := range networkNamespaces {
		netns := netns
		for _, iface := range ifaces {
			iface := iface

			handle, err := capture.NewBasic(ctx, log, iface, netns, conf)
			if err != nil {
				return nil, err
			}

			if linkType == layers.LinkTypeNull {
				linkType = handle.LinkType()
			}

			eg.Go(func() error {
				// Close the handle after it stops
				defer handle.Close()
				return handle.Start(ctx, forwardHandler)
			})
		}
	}

	errs := make(chan error)

	log.Debug("starting packet merger")
	heapDrainThreshold := 10
	flushInterval := time.Second
	mergeBufferSize := 100
	merger := capture.NewPacketMerger(
		log,
		[]capture.NamedPacketSource{{Name: "local-capture", PacketSource: capture.PacketSourceChan(packets)}},
		heapDrainThreshold, flushInterval, mergeBufferSize, 0,
	)

	go func() {
		// wait for the handles to return before closing packets. If any handles
		// encountered an error, send that error to ReadPacketData
		defer close(packets)
		err := eg.Wait()
		if err != nil {
			errs <- err
		}
	}()

	return &localCaptureSource{
		packets:  merger.PacketsCtx(ctx),
		errs:     errs,
		linkType: linkType,
	}, nil
}

func (lcs *localCaptureSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	select {
	case tp, ok := <-lcs.packets:
		if !ok {
			close(lcs.errs)
			return nil, gopacket.CaptureInfo{}, io.EOF
		}
		p := tp.(*capture.GoPacketWrapper).Packet
		return p.Data(), p.Metadata().CaptureInfo, nil
	case err := <-lcs.errs:
		close(lcs.errs)
		return nil, gopacket.CaptureInfo{}, err
	}
}

func (lcs *localCaptureSource) LinkType() layers.LinkType {
	return lcs.linkType
}

func normalizeFilename(ad *capperpb.AncillaryPacketData, outputFormat capperpb.PcapOutputFormat) string {
	var b strings.Builder
	b.WriteString("host:")
	b.WriteString(ad.NodeName)
	if ad.K8SPodName != "" {
		b.WriteString(":podNamespace:")
		b.WriteString(ad.K8SPodNamespace)
		b.WriteString(":pod:")
		b.WriteString(ad.K8SPodName)
	} else if ad.Netns != "" {
		b.WriteString(":netns:")
		netnsStr := strings.Trim(strings.ReplaceAll(ad.Netns, "/", "-"), "-")
		b.WriteString(netnsStr)
	}
	b.WriteString(":iface:")
	b.WriteString(ad.IfaceName)
	b.WriteString(".")
	b.WriteString(outputFormatExtension(outputFormat))
	return b.String()
}

func outputFormatExtension(outputFormat capperpb.PcapOutputFormat) string {
	switch outputFormat {
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAPNG:
		return "pcapng"
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAP, capperpb.PcapOutputFormat_OUTPUT_FORMAT_UNSPECIFIED:
		fallthrough
	default:
		return "pcap"
	}

}
