package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/devopsext/utils"
	"github.com/spf13/cobra"
)

// Version of the app
var VERSION = "unknown"

var rootLog = utils.GetLog()
var rootEnv = utils.GetEnvironment()

type rootOptions struct {
	LogFormat   string
	LogLevel    string
	LogTemplate string
}

var rootOpts = rootOptions{

	LogFormat:   rootEnv.Get("SHIPPER_LOG_FORMAT", "text").(string),
	LogLevel:    rootEnv.Get("SHIPPER_LOG_LEVEL", "info").(string),
	LogTemplate: rootEnv.Get("SHIPPER_LOG_TEMPLATE", "{{.func}} [{{.line}}]: {{.msg}}").(string),
}

func interceptSyscall() {

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	go func() {
		<-c
		rootLog.Info("Exiting...")
		os.Exit(1)
	}()
}

func Execute() {

	rootCmd := &cobra.Command{
		Use:   "shipper",
		Short: "Shipper",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			rootLog.CallInfo = true
			rootLog.Init(rootOpts.LogFormat, rootOpts.LogLevel, rootOpts.LogTemplate)

		},
		Run: func(cmd *cobra.Command, args []string) {

			rootLog.Info("Booting...")
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringVar(&rootOpts.LogFormat, "log-format", rootOpts.LogFormat, "Log format: json, text, stdout")
	flags.StringVar(&rootOpts.LogLevel, "log-level", rootOpts.LogLevel, "Log level: info, warn, error, debug, panic")
	flags.StringVar(&rootOpts.LogTemplate, "log-template", rootOpts.LogTemplate, "Log template")

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(VERSION)
		},
	})

	//rootCmd.AddCommand(GetWebsiteCmd())

	if err := rootCmd.Execute(); err != nil {
		rootLog.Error(err)
		os.Exit(1)
	}
}
