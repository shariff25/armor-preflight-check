package output

import (
	"bytes"
	"encoding/csv"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/catalog"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/engine"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/model"
	"github.com/shariff25/agent-goverance-OS/armor-preflight/internal/settings"
)

// FirewallHeader is the CSV header row.
var FirewallHeader = []string{"source_subnet", "destination", "port", "protocol", "direction", "purpose", "check_id"}

// FirewallRow is one egress rule a network team needs to add.
type FirewallRow struct {
	SourceSubnet string
	Destination  string
	Port         int
	Purpose      string
	CheckID      string
}

// FirewallInputs is what the CSV needs beyond the results.
type FirewallInputs struct {
	Catalog  *catalog.Catalog
	Settings *settings.Settings
	Topology engine.Topology
}

// FirewallRows returns one row per failed egress path: each (node pool,
// destination, port) where the TCP or TLS stage failed. DNS and HTTP
// failures are not firewall rules, so they are left out. When several checks
// report the same path, the row names the most specific check (for example
// CC-03 rather than NET-02 for a PCCS host).
func FirewallRows(results []model.Result, in FirewallInputs) []FirewallRow {
	type key struct {
		pool, dest string
		port       int
	}
	rows := map[key]FirewallRow{}
	for _, r := range results {
		if r.Scope.NodePool == "" || (r.Status != model.StatusFail && r.Status != model.StatusWarn) {
			continue
		}
		for _, e := range r.Evidence {
			if e.OK || (e.Stage != "tcp" && e.Stage != "tls") {
				continue
			}
			host, port, ok := splitTarget(e.Target)
			if !ok {
				continue
			}
			k := key{r.Scope.NodePool, host, port}
			if prev, seen := rows[k]; seen && !moreSpecific(r.ID, prev.CheckID) {
				continue
			}
			rows[k] = FirewallRow{
				SourceSubnet: sourceSubnet(r.Scope.NodePool, in),
				Destination:  host,
				Port:         port,
				Purpose:      purpose(in, host),
				CheckID:      r.ID,
			}
		}
	}
	out := make([]FirewallRow, 0, len(rows))
	for _, row := range rows {
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SourceSubnet != b.SourceSubnet {
			return a.SourceSubnet < b.SourceSubnet
		}
		if a.Destination != b.Destination {
			return a.Destination < b.Destination
		}
		return a.Port < b.Port
	})
	return out
}

// moreSpecific prefers any check over the generic egress check NET-02.
func moreSpecific(candidate, current string) bool {
	return current == "NET-02" && candidate != "NET-02"
}

func splitTarget(target string) (string, int, bool) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		return "", 0, false
	}
	return host, port, true
}

// sourceSubnet is the pool subnet from the settings, else the pool's node
// IPs as /32s, else a marker the network team cannot mistake for a subnet.
func sourceSubnet(pool string, in FirewallInputs) string {
	if in.Settings != nil {
		if np, ok := in.Settings.NodePools[pool]; ok && np.Subnet != "" {
			return np.Subnet
		}
	}
	var ips []string
	for _, node := range in.Topology.Pools[pool] {
		if ip := in.Topology.NodeIPs[node]; ip != "" {
			ips = append(ips, ip+"/32")
		}
	}
	if len(ips) > 0 {
		sort.Strings(ips)
		return strings.Join(ips, " ")
	}
	return "UNKNOWN (node pool " + pool + "; set nodePools." + pool + ".subnet)"
}

func purpose(in FirewallInputs, host string) string {
	if in.Catalog != nil && in.Settings != nil {
		if p := in.Catalog.PurposeOf(in.Settings, host); p != "" {
			return p
		}
	}
	return "Required by Armor"
}

// RenderFirewallCSV renders firewall-request.csv. It always has the header,
// so an empty file still shows its format.
func RenderFirewallCSV(rows []FirewallRow) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write(FirewallHeader); err != nil {
		return nil, err
	}
	for _, r := range rows {
		row := []string{r.SourceSubnet, r.Destination, strconv.Itoa(r.Port), "TCP", "outbound", r.Purpose, r.CheckID}
		for i := range row {
			row[i] = csvSafe(row[i])
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// csvSafe stops spreadsheet formula injection (CWE-1236): a cell starting
// with =, +, -, @, tab or carriage return is evaluated by Excel and Sheets,
// so it is prefixed with a quote. Real subnets, host names and IDs never
// start with those characters.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
