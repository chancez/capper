package cmd

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/chancez/capper/pkg/namespaces"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"
)

var listInterfacesCmd = &cobra.Command{
	Use:   "list-interfaces",
	Short: "",
	RunE:  runListInterfaces,
}

func init() {
	rootCmd.AddCommand(listInterfacesCmd)
	listInterfacesCmd.Flags().StringP("netns", "N", "", "List the interfaces in the specified network namespace")
}

func runListInterfaces(cmd *cobra.Command, args []string) error {
	netns, err := cmd.Flags().GetString("netns")
	if err != nil {
		return err
	}

	listIfaces := func(uint64) error {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return fmt.Errorf("error listing network interfaces: %w", err)
		}
		for i, iface := range ifaces {
			details := strings.Join(interfaceDetails(iface), ", ")
			fmt.Printf("%d.%s [%s]\n", i+1, iface.Name, details)
		}
		return nil
	}

	if netns != "" && runtime.GOOS == "linux" {
		return namespaces.RunInNetns(listIfaces, netns)
	}

	return listIfaces(0)
}

// Based on https://github.com/the-tcpdump-group/libpcap/blob/844f9d7ddff47c58f27b76c1620f38345ba73627/testprogs/findalldevstest.c#L215
func interfaceDetails(iface pcap.Interface) []string {
	var details []string
	if iface.Flags&PCAP_IF_UP != 0 {
		details = append(details, "Up")
	}
	if iface.Flags&PCAP_IF_RUNNING != 0 {
		details = append(details, "Running")
	}
	if iface.Flags&PCAP_IF_LOOPBACK != 0 {
		details = append(details, "Loopback")
	}

	if iface.Flags&PCAP_IF_WIRELESS != 0 {
		details = append(details, "Wireless")
		switch iface.Flags & PCAP_IF_CONNECTION_STATUS {
		case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
			details = append(details, "Association status unknown")
		case PCAP_IF_CONNECTION_STATUS_CONNECTED:
			details = append(details, "Associated")
		case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
			details = append(details, "Not associated")
		}
	} else {
		switch iface.Flags & PCAP_IF_CONNECTION_STATUS {
		case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
			details = append(details, "Unknown")
		case PCAP_IF_CONNECTION_STATUS_CONNECTED:
			details = append(details, "Connected")
		case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
			details = append(details, "Disconnected")
		}
	}

	if len(details) == 0 {
		details = []string{"none"}
	}
	return details
}

// https://github.com/the-tcpdump-group/libpcap/blob/844f9d7ddff47c58f27b76c1620f38345ba73627/pcap/pcap.h#L330C30-L338
const (
	PCAP_IF_LOOPBACK                         = 0x00000001 /* interface is loopback */
	PCAP_IF_UP                               = 0x00000002 /* interface is up */
	PCAP_IF_RUNNING                          = 0x00000004 /* interface is running */
	PCAP_IF_WIRELESS                         = 0x00000008 /* interface is wireless (*NOT* necessarily Wi-Fi!) */
	PCAP_IF_CONNECTION_STATUS                = 0x00000030 /* connection status: */
	PCAP_IF_CONNECTION_STATUS_UNKNOWN        = 0x00000000 /* unknown */
	PCAP_IF_CONNECTION_STATUS_CONNECTED      = 0x00000010 /* connected */
	PCAP_IF_CONNECTION_STATUS_DISCONNECTED   = 0x00000020 /* disconnected */
	PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE = 0x00000030 /* not applicable */
)
