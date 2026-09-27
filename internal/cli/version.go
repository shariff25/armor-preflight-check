package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/shariff25/armor-preflight-check/internal/buildinfo"
	"github.com/shariff25/armor-preflight-check/internal/catalog"
	"github.com/shariff25/armor-preflight-check/internal/exitcode"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Preflight version, catalog version and supported Armor versions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := catalog.Load()
			if err != nil {
				return exitcode.ToolFailure(err)
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "armor-preflight %s (commit %s, built %s)\n", buildinfo.Version, buildinfo.Commit, buildinfo.Date)
			fmt.Fprintf(out, "catalog %s\n", c.CatalogVersion)
			fmt.Fprintf(out, "supported Armor versions: %s\n", strings.Join(c.ArmorVersions, ", "))
			probe := buildinfo.ProbeImage
			if probe == "" {
				probe = "none (development build; pass --probe-image)"
			}
			fmt.Fprintf(out, "probe image: %s\n", probe)
			return nil
		},
	}
}
