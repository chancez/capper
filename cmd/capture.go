package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/cobra"
)

var captureCmd = &cobra.Command{
	Use:   "capture [filter]",
	Short: "Capture packets on the specified interface",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
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
		return capture(cmd.Context(), device, filter, snaplen, !noPromisc, outputFile)
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringP("interface", "i", "eth0", "Interface to capture packets on.")
	captureCmd.Flags().IntP("snaplen", "s", 262144, "Configure the snaplength.")
	captureCmd.Flags().BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	captureCmd.Flags().StringP("output", "o", "", "Store output into the file specified.")
}

func capture(ctx context.Context, device string, filter string, snaplen int, promisc bool, outputFile string) error {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return err
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplen); err != nil {
		return fmt.Errorf("error setting snaplen on handle: %w", err)
	}

	if err := inactive.SetPromisc(promisc); err != nil {
		return fmt.Errorf("error setting promiscuous mode on handle: %w", err)
	}

	if err := inactive.SetTimeout(time.Second); err != nil {
		return fmt.Errorf("error setting timeout on handle: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return fmt.Errorf("error activating handle: %w", err)
	}
	defer handle.Close()

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return fmt.Errorf("error setting filter on handle: %w", err)
		}
	}

	var pcapw *pcapgo.Writer
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output: %w", err)
		}
		defer f.Close()
		pcapw = pcapgo.NewWriter(f)
		if err := pcapw.WriteFileHeader(uint32(handle.SnapLen()), handle.LinkType()); err != nil {
			return fmt.Errorf("error writing file header: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if pcapw != nil {
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("error writing packet: %w", err)
			}
		} else {
			fmt.Println(packet)
		}
	}
	return nil
}
