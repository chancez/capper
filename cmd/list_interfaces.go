package cmd

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/spf13/cobra"
)

var listInterfacesCmd = &cobra.Command{
	Use:   "list-interfaces",
	Short: "",
	RunE:  runListInterfaces,
}

func init() {
	rootCmd.AddCommand(listInterfacesCmd)
}

func runListInterfaces(cmd *cobra.Command, args []string) error {
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
