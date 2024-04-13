package cmd

import (
	"context"
	"log"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "capper",
	Short:         "Capper captures packets",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	ctx := context.Background()
	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		log.Fatalf("capper encountered an error: %s", err)
	}
}
