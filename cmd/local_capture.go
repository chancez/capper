package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/containerd"
	"github.com/spf13/cobra"
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

	var netns string
	if captureOpts.K8sNamespace != "" && captureOpts.K8sPod != "" {
		containerdSock := "/run/containerd/containerd.sock"
		captureOpts.Logger.Debug("connecting to containerd", "addr", containerdSock)
		client, err := containerd.New(containerdSock)
		if err != nil {
			return fmt.Errorf("error connecting to containerd: %w", err)
		}
		defer client.Close()

		captureOpts.Logger.Debug("looking up k8s pod in containerd", "pod", captureOpts.K8sPod, "namespace", captureOpts.K8sNamespace)
		netns, err = containerd.GetPodNetns(ctx, client, captureOpts.K8sPod, captureOpts.K8sNamespace)
		if err != nil {
			return fmt.Errorf("error getting pod namespace: %w", err)
		}
		if netns == "" {
			return fmt.Errorf("could not find netns for pod '%s/%s'", captureOpts.K8sNamespace, captureOpts.K8sPod)
		}
		captureOpts.Logger.Debug("found netns for pod", "pod", captureOpts.K8sPod, "namespace", captureOpts.K8sNamespace, "netns", netns)
		captureOpts.Netns = netns
	}

	return localCapture(ctx, captureOpts.Logger, captureOpts.Interfaces, captureOpts.Netns, captureOpts.CaptureConfig, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

// localCapture runs a packet capture and stores the output to the specified file or
// logs the packets to stdout with the configured logger if outputFile is
// empty.
// If alwaysPrint is true; it prints regardless whether outputFile is empty.
func localCapture(ctx context.Context, log *slog.Logger, ifaces []string, netns string, conf capture.Config, outputFile string, alwaysPrint bool) error {
	handle, err := newCapture(ctx, log, ifaces, netns, conf)
	if err != nil {
		return err
	}
	defer handle.Close()
	linkType := handle.LinkType()
	var handlers []capture.PacketHandler
	if alwaysPrint || outputFile == "" {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputFile != "" {
		var w io.Writer
		if outputFile == "-" {
			w = os.Stdout
		} else {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			w = f
			defer f.Close()
		}
		writeHandler, err := capture.NewPcapWriterHandler(w, linkType, uint32(conf.Snaplen))
		if err != nil {
			return err
		}
		handlers = append(handlers, writeHandler)
	}
	handler := capture.ChainPacketHandlers(handlers...)

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return nil
}

func newCapture(ctx context.Context, log *slog.Logger, ifaces []string, netns string, conf capture.Config) (capture.Capture, error) {
	if len(ifaces) >= 2 {
		return capture.NewMulti(ctx, log, ifaces, netns, conf)
	}

	var iface string
	if len(ifaces) == 1 {
		iface = ifaces[0]
	}
	return capture.NewBasic(ctx, log, iface, netns, conf)
}
