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

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/containerd"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket/layers"
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

	iface := ""
	if len(ifaces) != 0 {
		iface = ifaces[0]
	}

	netns := ""
	if len(netNamespaces) != 0 {
		netns = netNamespaces[0]
	}

	handle, err := capture.NewBasic(ctx, log, iface, netns, conf)
	if err != nil {
		return err
	}
	defer handle.Close()
	linkType := handle.LinkType()

	handler := newCommonHandler(linkType, uint32(conf.Snaplen), printPackets, outputPath, isDir)
	defer handler.Flush()

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return nil
}

// func localCaptureMultiNamespace(ctx context.Context, log *slog.Logger, ifaces []string, netNamespaces []string, conf capture.Config, outputDir string, alwaysPrint bool) error {
// 	if len(netNamespaces) < 2 {
// 		return errors.New("localCaptureMultiNamespace requires at least 2 namespaces")
// 	}
// 	if outputDir == "" {
// 		return errors.New("--output-file is not specified, multi-namespace capture requires --output-file to point to a directory")
// 	}
// 	fi, err := os.Stat(outputDir)
// 	if err != nil && !errors.Is(err, os.ErrNotExist) {
// 		return err
// 	}
// 	if err == nil && fi.IsDir() {
// 		return fmt.Errorf("%s is not a directory, multi-namespace capture requires --output-file to point to a directory", outputDir)
// 	}

// 	var eg errgroup.Group
// 	for _, netns := range netNamespaces {
// 		// Create a capture per netns
// 		handle, err := newCapture(ctx, log, ifaces, netns, conf)
// 		if err != nil {
// 			return err
// 		}
// 		defer handle.Close()
// 		linkType := handle.LinkType()

// 		var handlers []capture.PacketHandler
// 		if alwaysPrint || outputDir == "" {
// 			handlers = append(handlers, capture.PacketPrinterHandler)
// 		}
// 		if outputDir != "" {
// 			// store each capture into it's own file in the outputDirectory
// 			hostname, _ := os.Hostname()
// 			fileName := normalizeFilename(hostname, netns, handle.Interface().GetName(), conf.OutputFormat)
// 			f, err := os.Create(filepath.Join(outputDir, fileName))
// 			if err != nil {
// 				return fmt.Errorf("error opening output: %w", err)
// 			}
// 			defer f.Close()
// 			writeHandler, err := newWriteHandler(f, linkType, uint32(conf.Snaplen), conf.OutputFormat, handle.Interface())
// 			if err != nil {
// 				return err
// 			}
// 			handlers = append(handlers, writeHandler)
// 		}

// 		eg.Go(func() error {
// 			err = handle.Start(ctx, capture.ChainPacketHandlers(handlers...))
// 			if err != nil {
// 				return fmt.Errorf("error occurred while capturing packets: %w", err)
// 			}
// 			return nil
// 		})
// 	}

// 	err = eg.Wait()
// 	if errors.Is(err, context.Canceled) {
// 		return nil
// 	}
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }

func normalizePodFilename(pod *capperpb.Pod, ifaceName string, outputFormat capperpb.PcapOutputFormat) string {
	var b strings.Builder
	b.WriteString("pod:")
	b.WriteString(pod.GetNamespace())
	b.WriteString(":")
	b.WriteString(pod.GetName())
	b.WriteString(":iface:")
	b.WriteString(ifaceName)
	b.WriteString(".")
	b.WriteString(outputFormatExtension(outputFormat))
	return b.String()
}

func normalizeFilename(host string, netns string, ifaceName string, outputFormat capperpb.PcapOutputFormat) string {
	var b strings.Builder
	b.WriteString("host:")
	b.WriteString(host)
	if runtime.GOOS == "linux" {
		if netns != "" {
			b.WriteString(":netns:")
			netnsStr := strings.Trim(strings.ReplaceAll(netns, "/", "-"), "-")
			b.WriteString(netnsStr)
		}
	}
	b.WriteString(":iface:")
	b.WriteString(ifaceName)
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

func newWriteHandler(w io.Writer, linkType layers.LinkType, snaplen uint32, outputFormat capperpb.PcapOutputFormat, iface *capperpb.CaptureInterface) (capture.PacketHandler, error) {
	var writeHandler capture.PacketHandler
	var err error
	switch outputFormat {
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAPNG:
		writeHandler, err = capture.NewPcapNgWriterHandler(w, linkType, snaplen, iface)
	case capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAP, capperpb.PcapOutputFormat_OUTPUT_FORMAT_UNSPECIFIED:
		fallthrough
	default:
		writeHandler, err = capture.NewPcapWriterHandler(w, linkType, snaplen)
	}
	return writeHandler, err
}
