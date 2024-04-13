package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
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
		alwaysPrint, err := cmd.Flags().GetBool("print")
		if err != nil {
			return err
		}

		return capture(cmd.Context(), device, filter, snaplen, !noPromisc, outputFile, alwaysPrint)
	},
}

func init() {
	rootCmd.AddCommand(captureCmd)
	captureCmd.Flags().StringP("interface", "i", "eth0", "Interface to capture packets on.")
	captureCmd.Flags().IntP("snaplen", "s", 262144, "Configure the snaplength.")
	captureCmd.Flags().BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	captureCmd.Flags().StringP("output", "o", "", "Store output into the file specified.")
	captureCmd.Flags().BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
}

func newHandle(ctx context.Context, device string, filter string, snaplen int, promisc bool) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplen); err != nil {
		return nil, fmt.Errorf("error setting snaplen on handle: %w", err)
	}

	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("error setting promiscuous mode on handle: %w", err)
	}

	if err := inactive.SetTimeout(time.Second); err != nil {
		return nil, fmt.Errorf("error setting timeout on handle: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("error activating handle: %w", err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return nil, fmt.Errorf("error setting filter on handle: %w", err)
		}
	}
	return handle, nil
}

func capture(ctx context.Context, device string, filter string, snaplen int, promisc bool, outputFile string, alwaysPrint bool) error {
	handle, err := newHandle(ctx, device, filter, snaplen, promisc)
	if err != nil {
		return fmt.Errorf("error creating handle: %w", err)
	}
	defer handle.Close()

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
		if pcapw == nil || alwaysPrint {
			fmt.Println(packet)
		}
		if pcapw != nil {
			if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
				return fmt.Errorf("error writing packet: %w", err)
			}
		}
	}
	return nil
}
