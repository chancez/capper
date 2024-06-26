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
		case captureOpts.K8sPod != "":
			flag = "--k8s-pod"
		case captureOpts.K8sNamespace != "":
			flag = "--k8s-namespace"
		}
		if flag != "" {
			return fmt.Errorf("%s is only valid on Linux", flag)
		}
	}

	if captureOpts.K8sNamespace != "" && captureOpts.K8sPod != "" {
		containerdSock := "/run/containerd/containerd.sock"
		captureOpts.Logger.Debug("connecting to containerd", "addr", containerdSock)
		client, err := containerd.New(containerdSock)
		if err != nil {
			return fmt.Errorf("error connecting to containerd: %w", err)
		}
		defer client.Close()

		captureOpts.Logger.Debug("looking up k8s pod in containerd", "pod", captureOpts.K8sPod, "namespace", captureOpts.K8sNamespace)
		netns, err := containerd.GetPodNetns(ctx, client, captureOpts.K8sPod, captureOpts.K8sNamespace)
		if err != nil {
			return fmt.Errorf("error getting pod namespace: %w", err)
		}
		if netns == "" {
			return fmt.Errorf("could not find netns for pod '%s/%s'", captureOpts.K8sNamespace, captureOpts.K8sPod)
		}
		captureOpts.Logger.Debug("found netns for pod", "pod", captureOpts.K8sPod, "namespace", captureOpts.K8sNamespace, "netns", netns)
		netNamespaces = append(netNamespaces, netns)
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
				fileName = filepath.Join(outputDir, normalizeFilename(hostname, netns, handle.Interfaces()))
			}
			f, err := os.Create(fileName)
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
			fileName := normalizeFilename(hostname, netns, handle.Interfaces())
			f, err := os.Create(filepath.Join(outputDir, fileName))
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			defer f.Close()
			writeHandler, err := capture.NewPcapWriterHandler(f, linkType, uint32(conf.Snaplen))
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

func normalizeFilename(host string, netns string, ifaces []string) string {
	ifaceStr := strings.Join(ifaces, ",")
	if runtime.GOOS != "linux" {
		return fmt.Sprintf("host:%s:ifaces:%s.pcap", host, ifaceStr)

	}
	netnsStr := strings.Trim(strings.ReplaceAll(netns, "/", "-"), "-")
	return fmt.Sprintf("host:%s:netns:%s:ifaces:%s.pcap", host, netnsStr, ifaceStr)
}
