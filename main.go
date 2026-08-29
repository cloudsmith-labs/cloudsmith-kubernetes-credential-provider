package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"

	exitProcess             = os.Exit
	processArgs             = os.Args[1:]
	processStdin  io.Reader = os.Stdin
	processStdout io.Writer = os.Stdout
	processStderr io.Writer = os.Stderr
	setFlag                 = flag.Set
	initLogs                = logs.InitLogs
)

func main() {
	klog.InitFlags(nil)
	exitProcess(run(context.Background(), processArgs, processStdin, processStdout, processStderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	command := newRootCommand(stdin, stdout, stderr)
	command.SetArgs(args)
	if err := command.ExecuteContext(ctx); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func newRootCommand(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	var configFile string

	rootCommand := &cobra.Command{
		Use:           "cloudsmith-kubernetes-credential-provider",
		Short:         "Kubernetes credential provider for Cloudsmith registries",
		Version:       fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(command *cobra.Command, _ []string) error {
			config, err := LoadConfig(configFile)
			if err != nil {
				return err
			}
			if err := setupLogging(config.LogLevel); err != nil {
				return err
			}
			defer logs.FlushLogs()

			provider := NewCloudsmithCredentialProvider(config)
			requestBudget := time.Duration(config.MaxRetryAttempts) * (config.HTTPTimeout + config.RetryBackoffCap)
			requestContext, cancel := context.WithTimeout(command.Context(), requestBudget)
			defer cancel()
			return processRequest(requestContext, provider, stdin, stdout)
		},
	}
	rootCommand.SetIn(stdin)
	rootCommand.SetOut(stdout)
	rootCommand.SetErr(stderr)
	rootCommand.PersistentFlags().StringVar(&configFile, "config", "", "Path to the configuration file")

	rootCommand.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(command.OutOrStdout(), command.Root().Version)
			return err
		},
	})
	return rootCommand
}

func processRequest(
	ctx context.Context,
	provider *CloudsmithCredentialProvider,
	input io.Reader,
	output io.Writer,
) error {
	var request credentialproviderapi.CredentialProviderRequest
	decoder := json.NewDecoder(input)
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode credential provider request: %w", err)
	}

	if decoder.More() {
		return fmt.Errorf("decode credential provider request: multiple JSON values")
	}

	response, err := provider.GetCredentials(ctx, &request)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(output).Encode(response); err != nil {
		return fmt.Errorf("encode credential provider response: %w", err)
	}
	return nil
}

func setupLogging(logLevel string) error {
	var verbosity int
	switch strings.ToLower(logLevel) {
	case "debug":
		verbosity = 4
	case "info":
		verbosity = 2
	case "warn", "warning":
		verbosity = 1
	case "error":
		verbosity = 0
	default:
		return fmt.Errorf("unsupported log_level %q", logLevel)
	}
	if err := setFlag("v", strconv.Itoa(verbosity)); err != nil {
		return fmt.Errorf("set log verbosity: %w", err)
	}
	initLogs()
	return nil
}
