package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
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
	localCaptureCmd.Flags().StringP("interface", "i", "eth0", "Interface to capture packets on.")
	localCaptureCmd.Flags().IntP("snaplen", "s", 262144, "Configure the snaplength.")
	localCaptureCmd.Flags().BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	localCaptureCmd.Flags().StringP("output", "o", "", "Store output into the file specified.")
	localCaptureCmd.Flags().BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
	localCaptureCmd.Flags().Uint64P("num-packets", "n", 0, "Number of packets to capture.")
	localCaptureCmd.Flags().DurationP("duration", "d", 0, "Duration to capture packets.")
}

func runLocalCapture(cmd *cobra.Command, args []string) error {
	var filter string
	if len(args) == 1 {
		filter = args[0]
	}
	device, err := cmd.Flags().GetString("interface")
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
	return localCapture(cmd.Context(), device, filter, snaplen, !noPromisc, outputFile, alwaysPrint, numPackets, dur)
}

func localCapture(ctx context.Context, device string, filter string, snaplen int, promisc bool, outputFile string, alwaysPrint bool, numPackets uint64, captureDuration time.Duration) error {
	var wh *packetWriterHandler
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output: %w", err)
		}
		defer f.Close()
		wh = newPacketWriterHandler(f)
	}

	handler := packetHandlerFunc(func(h *pcap.Handle, p gopacket.Packet) error {
		if wh == nil || alwaysPrint {
			fmt.Println(p)
		}
		if wh != nil {
			// Write the packet to the file
			if err := wh.HandlePacket(h, p); err != nil {
				return err
			}
		}

		return nil
	})
	pcap := newPacketCapture(slog.Default(), handler)
	err := pcap.Run(ctx, device, filter, snaplen, promisc, numPackets, captureDuration)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return nil
}
