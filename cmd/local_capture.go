package cmd

import (
	"github.com/chancez/capper/pkg/capture"
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
	return capture.Local(cmd.Context(), device, filter, snaplen, !noPromisc, outputFile, alwaysPrint, numPackets, dur)
}
