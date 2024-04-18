package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/chancez/capper/pkg/capture"
	"github.com/chancez/capper/pkg/containerd"
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
	localCaptureCmd.Flags().StringP("interface", "i", "", "Interface to capture packets on.")
	localCaptureCmd.Flags().IntP("snaplen", "s", 262144, "Configure the snaplength.")
	localCaptureCmd.Flags().BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	localCaptureCmd.Flags().StringP("output", "o", "", "Store output into the file specified.")
	localCaptureCmd.Flags().BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
	localCaptureCmd.Flags().Uint64P("num-packets", "n", 0, "Number of packets to capture.")
	localCaptureCmd.Flags().DurationP("duration", "d", 0, "Duration to capture packets.")
	localCaptureCmd.Flags().StringP("netns", "N", "", "Run the capture in the specified network namespace")
	localCaptureCmd.Flags().String("k8s-pod", "", "Run the capture on the target k8s pod. Requires containerd. Must also set k8s-namespace.")
	localCaptureCmd.Flags().String("k8s-namespace", "", "Run the capture on the target k8s pod in namespace. Requires containerd. Must also set k8s-pod.")
}

func runLocalCapture(cmd *cobra.Command, args []string) error {
	var filter string
	if len(args) == 1 {
		filter = args[0]
	}
	iface, err := cmd.Flags().GetString("interface")
	if err != nil {
		return err
	}
	snaplen, err := cmd.Flags().GetInt("snaplen")
	if err != nil {
		return err
	}
	noPromisc, err := cmd.Flags().GetBool("no-promiscuous-mode")
	if err != nil {
		return err
	}
	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	alwaysPrint, err := cmd.Flags().GetBool("print")
	if err != nil {
		return err
	}
	numPackets, err := cmd.Flags().GetUint64("num-packets")
	if err != nil {
		return err
	}
	dur, err := cmd.Flags().GetDuration("duration")
	if err != nil {
		return err
	}
	netns, err := cmd.Flags().GetString("netns")
	if err != nil {
		return err
	}

	k8sPod, err := cmd.Flags().GetString("k8s-pod")
	if err != nil {
		return err
	}
	k8sNs, err := cmd.Flags().GetString("k8s-namespace")
	if err != nil {
		return err
	}

	log := slog.Default()
	ctx := cmd.Context()
	if k8sNs != "" && k8sPod != "" {
		containerdSock := "/run/containerd/containerd.sock"
		log.Debug("connecting to containerd", "addr", containerdSock)
		client, err := containerd.New(containerdSock)
		if err != nil {
			return fmt.Errorf("error connecting to containerd: %w", err)
		}
		defer client.Close()

		log.Debug("looking up k8s pod in containerd", "pod", k8sPod, "namespace", k8sNs)
		netns, err = containerd.GetPodNetns(ctx, client, k8sPod, k8sNs)
		if err != nil {
			return fmt.Errorf("error getting pod namespace: %w", err)
		}
		if netns == "" {
			return fmt.Errorf("could not find netns for pod '%s/%s'", k8sNs, k8sPod)
		}
		log.Debug("configuring netns for pod", "pod", k8sPod, "namespace", k8sNs, "netns", netns)
	}

	conf := capture.Config{
		Filter:          filter,
		Snaplen:         snaplen,
		Promisc:         !noPromisc,
		NumPackets:      numPackets,
		CaptureDuration: dur,
		Netns:           netns,
	}
	return localCapture(ctx, log, iface, conf, outputFile, alwaysPrint)
}

// localCapture runs a packet capture and stores the output to the specified file or
// logs the packets to stdout with the configured logger if outputFile is
// empty.
// If alwaysPrint is true; it prints regardless whether outputFile is empty.
func localCapture(ctx context.Context, log *slog.Logger, iface string, conf capture.Config, outputFile string, alwaysPrint bool) error {
	var handlers []capture.PacketHandler
	if alwaysPrint || outputFile == "" {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output: %w", err)
		}
		defer f.Close()
		writeHandler := capture.NewPacketWriterHandler(f, uint32(conf.Snaplen), layers.LinkTypeEthernet)
		handlers = append(handlers, writeHandler)
	}
	handler := capture.ChainPacketHandlers(handlers...)

	err := capture.Run(ctx, log, iface, conf, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return nil
}
