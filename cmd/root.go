package cmd

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:           "capper",
	Short:         "Capper captures packets",
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := rootCmd.ExecuteContext(ctx)
	if err != nil {
		slog.Error("capper encountered an error", "error", err)
		os.Exit(1)
	}
}
