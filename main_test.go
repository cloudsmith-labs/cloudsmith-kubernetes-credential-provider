package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	credentialproviderapi "k8s.io/kubelet/pkg/apis/credentialprovider/v1"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) {
	return 0, errTest
}

func TestProcessRequestRejectsMultipleJSONValues(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	err := processRequest(
		context.Background(),
		NewCloudsmithCredentialProvider(testConfig()),
		strings.NewReader(`{} {}`),
		&output,
	)
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("processRequest() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("processRequest() wrote output on failure: %q", output.String())
	}
}

func TestVersionCommand(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	command := newRootCommand(strings.NewReader(""), &output, &output)
	command.SetArgs([]string{"version"})
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("version command error = %v", err)
	}
	if !strings.Contains(output.String(), version) {
		t.Fatalf("version output = %q", output.String())
	}
}

func TestMainFunction(t *testing.T) {
	oldExit := exitProcess
	oldArgs := processArgs
	oldStdin := processStdin
	oldStdout := processStdout
	oldStderr := processStderr
	t.Cleanup(func() {
		exitProcess = oldExit
		processArgs = oldArgs
		processStdin = oldStdin
		processStdout = oldStdout
		processStderr = oldStderr
	})

	exitCode := -1
	exitProcess = func(code int) { exitCode = code }
	processArgs = []string{"version"}
	processStdin = strings.NewReader("")
	processStdout = io.Discard
	processStderr = io.Discard

	main()
	if exitCode != 0 {
		t.Fatalf("main() exit code = %d, want 0", exitCode)
	}
}

func TestRun(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var output bytes.Buffer
		if got := run(context.Background(), []string{"version"}, strings.NewReader(""), &output, &output); got != 0 {
			t.Fatalf("run() = %d, want 0", got)
		}
	})

	t.Run("error", func(t *testing.T) {
		var output bytes.Buffer
		if got := run(context.Background(), []string{"unexpected"}, strings.NewReader(""), &output, &output); got != 1 {
			t.Fatalf("run() = %d, want 1", got)
		}
		if !strings.Contains(output.String(), "unknown command") {
			t.Fatalf("run() output = %q", output.String())
		}
	})
}

func TestRootCommandErrors(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		command := newRootCommand(strings.NewReader("{}"), io.Discard, io.Discard)
		command.SetArgs([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml")})
		if err := command.ExecuteContext(context.Background()); err == nil {
			t.Fatal("ExecuteContext() error = nil")
		}
	})

	t.Run("logging", func(t *testing.T) {
		path := writeConfig(t, "log_level: verbose\n")
		command := newRootCommand(strings.NewReader("{}"), io.Discard, io.Discard)
		command.SetArgs([]string{"--config", path})
		if err := command.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "unsupported log_level") {
			t.Fatalf("ExecuteContext() error = %v", err)
		}
	})

	t.Run("request", func(t *testing.T) {
		oldSetFlag := setFlag
		oldInitLogs := initLogs
		setFlag = func(string, string) error { return nil }
		initLogs = func() {}
		t.Cleanup(func() {
			setFlag = oldSetFlag
			initLogs = oldInitLogs
		})

		path := writeConfig(t, "log_level: info\n")
		command := newRootCommand(strings.NewReader("not-json"), io.Discard, io.Discard)
		command.SetArgs([]string{"--config", path})
		if err := command.ExecuteContext(context.Background()); err == nil || !strings.Contains(err.Error(), "decode credential") {
			t.Fatalf("ExecuteContext() error = %v", err)
		}
	})

	t.Run("version write", func(t *testing.T) {
		command := newRootCommand(strings.NewReader(""), errorWriter{}, io.Discard)
		command.SetArgs([]string{"version"})
		if err := command.ExecuteContext(context.Background()); !errors.Is(err, errTest) {
			t.Fatalf("ExecuteContext() error = %v", err)
		}
	})
}

func TestProcessRequest(t *testing.T) {
	validRequest := fmt.Sprintf(
		`{"apiVersion":%q,"kind":"CredentialProviderRequest","image":"registry.example/repo/image","serviceAccountToken":"oidc"}`,
		credentialproviderapi.SchemeGroupVersion.String(),
	)

	tests := []struct {
		name     string
		input    string
		output   io.Writer
		provider func() *CloudsmithCredentialProvider
		want     string
	}{
		{
			name:   "decode error",
			input:  "{",
			output: io.Discard,
			want:   "decode credential provider request",
		},
		{
			name:   "trailing malformed JSON",
			input:  "{} {",
			output: io.Discard,
			want:   "decode credential provider request",
		},
		{
			name:   "provider error",
			input:  "{}",
			output: io.Discard,
			want:   "unsupported credential provider API version",
		},
		{
			name:   "encode error",
			input:  validRequest,
			output: errorWriter{},
			provider: func() *CloudsmithCredentialProvider {
				provider := NewCloudsmithCredentialProvider(testConfig())
				provider.httpClient = staticResponse(http.StatusOK, `{"token":"opaque"}`)
				return provider
			},
			want: "encode credential provider response",
		},
		{
			name:   "success",
			input:  validRequest,
			output: &bytes.Buffer{},
			provider: func() *CloudsmithCredentialProvider {
				provider := NewCloudsmithCredentialProvider(testConfig())
				provider.httpClient = staticResponse(http.StatusOK, `{"token":"opaque"}`)
				return provider
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider := NewCloudsmithCredentialProvider(testConfig())
			if test.provider != nil {
				provider = test.provider()
			}
			err := processRequest(context.Background(), provider, strings.NewReader(test.input), test.output)
			if test.want == "" && err != nil {
				t.Fatalf("processRequest() error = %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("processRequest() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestSetupLogging(t *testing.T) {
	oldSetFlag := setFlag
	oldInitLogs := initLogs
	t.Cleanup(func() {
		setFlag = oldSetFlag
		initLogs = oldInitLogs
	})

	var gotValues []string
	initCalls := 0
	setFlag = func(name, value string) error {
		if name != "v" {
			t.Errorf("flag name = %q", name)
		}
		gotValues = append(gotValues, value)
		return nil
	}
	initLogs = func() { initCalls++ }

	for _, level := range []string{"DEBUG", "info", "warn", "warning", "error"} {
		if err := setupLogging(level); err != nil {
			t.Fatalf("setupLogging(%q) error = %v", level, err)
		}
	}
	if got := strings.Join(gotValues, ","); got != "4,2,1,1,0" {
		t.Fatalf("verbosity values = %q", got)
	}
	if initCalls != len(gotValues) {
		t.Fatalf("InitLogs calls = %d, want %d", initCalls, len(gotValues))
	}

	if err := setupLogging("trace"); err == nil {
		t.Fatal("setupLogging(trace) error = nil")
	}
	setFlag = func(string, string) error { return errTest }
	if err := setupLogging("info"); !errors.Is(err, errTest) {
		t.Fatalf("setupLogging(info) error = %v", err)
	}
}
