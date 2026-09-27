package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/exitcode"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/output"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/redact"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

type bundleOptions struct {
	outputDir    string
	settingsFile string
	listOnly     bool
	yes          bool
}

func newBundleCmd() *cobra.Command {
	o := &bundleOptions{}
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Package the latest run into a redacted archive for a support ticket",
		Long: "Packages the latest run's result.json with tool and cluster versions into bundle.tgz.\n" +
			"The contents are listed before anything is written, and the bundle is only written once you confirm (or pass --yes).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return o.run(cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.outputDir, "output", "o", DefaultOutputDir, "output directory of the run to bundle")
	f.StringVarP(&o.settingsFile, "settings", "f", "", "settings file, so the secrets it names are also masked in the bundle")
	f.BoolVar(&o.listOnly, "list", false, "list the bundle contents without writing it")
	f.BoolVarP(&o.yes, "yes", "y", false, "write the bundle without asking for confirmation")
	return cmd
}

func (o *bundleOptions) run(in io.Reader, stdout io.Writer) (err error) {
	red := redact.New()
	if o.settingsFile != "" {
		st, err := settings.Load(o.settingsFile)
		if err != nil {
			return exitcode.ToolFailure(err)
		}
		red = newRedactor(st)
	}
	out := redact.NewWriter(red, stdout)
	defer func() {
		out.Flush()
		err = red.Error(err)
	}()

	rec, err := output.ReadRecord(o.outputDir)
	if err != nil {
		return exitcode.ToolFailure(err)
	}
	entries, err := output.BuildBundle(rec, red, now())
	if err != nil {
		return exitcode.ToolFailure(err)
	}
	output.ListBundle(out, rec, entries)
	if o.listOnly {
		return nil
	}

	path := filepath.Join(o.outputDir, output.BundleFile)
	if !o.yes {
		fmt.Fprintf(out, "\nWrite %s? [y/N] ", path)
		out.Flush()
		answer, rerr := bufio.NewReader(in).ReadString('\n')
		answer = strings.ToLower(strings.TrimSpace(answer))
		if rerr != nil && answer == "" {
			fmt.Fprintln(out)
			return exitcode.ToolFailure(errors.New("bundle not written: no confirmation (run it interactively, or pass --yes)"))
		}
		if answer != "y" && answer != "yes" {
			fmt.Fprintln(out, "Not written.")
			return nil
		}
	}
	if err := output.WriteBundle(path, rec, entries, now()); err != nil {
		return exitcode.ToolFailure(err)
	}
	fmt.Fprintf(out, "\nWrote %s. Attach it to the support ticket.\n", path)
	return nil
}
