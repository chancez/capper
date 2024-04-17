package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/chancez/capper/pkg/namespaces"
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

	listIfaces := func() error {
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("error listing network interfaces: %w", err)
		}
		b, err := json.MarshalIndent(ifaces, "", "  ")
		if err != nil {
			return fmt.Errorf("error marshalling network interfaces: %w", err)
		}
		fmt.Println(string(b))
		return nil
	}

	if netns != "" && runtime.GOOS == "linux" {
		return namespaces.RunInNetns(listIfaces, netns)
	}

	return listIfaces()
}
