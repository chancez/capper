package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/containerd"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket/layers"
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

	if len(netNamespaces) > 1 {
		return localCaptureMultiNamespace(ctx, captureOpts.Logger, captureOpts.Interfaces, netNamespaces, captureOpts.CaptureConfig, captureOpts.OutputFile, captureOpts.AlwaysPrint)
	}

	var netns string
	if len(netNamespaces) == 1 {
		netns = netNamespaces[0]
	}
	return localCapture(ctx, captureOpts.Logger, captureOpts.Interfaces, netns, captureOpts.CaptureConfig, captureOpts.OutputFile, captureOpts.AlwaysPrint)
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
			fi, err := os.Stat(outputFile)
			if err != nil {
				return err
			}

			fileName := outputFile
			// if the output is a directory, generate a filename and store it in that directory
			if fi.IsDir() {
				outputDir := outputFile
				hostname, _ := os.Hostname()
				fileName = filepath.Join(outputDir, normalizeFilename(hostname, netns, handle.Interfaces(), conf.OutputFormat))
			}
			f, err := os.Create(fileName)
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			w = f
			defer f.Close()
		}

		captureInterfaces := handle.Interfaces()
		writeHandler, err := newWriteHandler(w, linkType, uint32(conf.Snaplen), conf.OutputFormat, captureInterfaces[0])
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

func localCaptureMultiNamespace(ctx context.Context, log *slog.Logger, ifaces []string, netNamespaces []string, conf capture.Config, outputDir string, alwaysPrint bool) error {
	if len(netNamespaces) < 2 {
		return errors.New("localCaptureMultiNamespace requires at least 2 namespaces")
	}
	if outputDir == "" {
		return errors.New("--output-file is not specified, multi-namespace capture requires --output-file to point to a directory")
	}
	fi, err := os.Stat(outputDir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory, multi-namespace capture requires --output-file to point to a directory", outputDir)
	}

	var eg errgroup.Group
	for _, netns := range netNamespaces {
		// Create a capture per netns
		handle, err := newCapture(ctx, log, ifaces, netns, conf)
		if err != nil {
			return err
		}
		defer handle.Close()
		linkType := handle.LinkType()

		var handlers []capture.PacketHandler
		if alwaysPrint || outputDir == "" {
			handlers = append(handlers, capture.PacketPrinterHandler)
		}
		if outputDir != "" {
			// store each capture into it's own file in the outputDirectory
			hostname, _ := os.Hostname()
			fileName := normalizeFilename(hostname, netns, handle.Interfaces(), conf.OutputFormat)
			f, err := os.Create(filepath.Join(outputDir, fileName))
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			defer f.Close()
			// TODO: Probably need to replace capture.NewMulti and just handle everything at the caller.
			captureInterfaces := handle.Interfaces()
			writeHandler, err := newWriteHandler(f, linkType, uint32(conf.Snaplen), conf.OutputFormat, captureInterfaces[0])
			if err != nil {
				return err
			}
			handlers = append(handlers, writeHandler)
		}

		eg.Go(func() error {
			err = handle.Start(ctx, capture.ChainPacketHandlers(handlers...))
			if err != nil {
				return fmt.Errorf("error occurred while capturing packets: %w", err)
			}
			return nil
		})
	}

	err = eg.Wait()
	if errors.Is(err, context.Canceled) {
		return nil
	}
	if err != nil {
		return err
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

func normalizePodFilename(pod *capperpb.Pod, ifaces []string, outputFormat capture.PcapOutputFormat) string {
	var b strings.Builder
	b.WriteString("pod:")
	b.WriteString(pod.GetNamespace())
	b.WriteString(":")
	b.WriteString(pod.GetName())
	if len(ifaces) != 0 {
		b.WriteString(":ifaces:")
		for i, iface := range ifaces {
			b.WriteString(iface)
			if i != len(ifaces)-1 {
				b.WriteString(",")
			}
		}
	}
	b.WriteString(".")
	b.WriteString(outputFormat.String())
	return b.String()
}

func normalizeFilename(host string, netns string, ifaces []string, outputFormat capture.PcapOutputFormat) string {
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
	if len(ifaces) != 0 {
		b.WriteString(":ifaces:")
		for i, iface := range ifaces {
			b.WriteString(iface)
			if i != len(ifaces)-1 {
				b.WriteString(",")
			}
		}
	}
	b.WriteString(".")
	b.WriteString(outputFormat.String())
	return b.String()
}

func newWriteHandler(w io.Writer, linkType layers.LinkType, snaplen uint32, outputFormat capture.PcapOutputFormat, iface string) (capture.PacketHandler, error) {
	var writeHandler capture.PacketHandler
	var err error
	switch outputFormat {
	case capture.PcapNgFormat:
		writeHandler, err = capture.NewPcapNgWriterHandler(w, linkType, snaplen, iface)
	case capture.PcapFormat:
		fallthrough
	default:
		writeHandler, err = capture.NewPcapWriterHandler(w, linkType, snaplen)
	}
	return writeHandler, err
}
