package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

type Result struct {
	Domain        string   `json:"domain"`
	PrimaryMX     string   `json:"primary_mx,omitempty"`
	Provider      string   `json:"provider,omitempty"`
	SecurityStack []string `json:"security_stack,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	Organisation  string   `json:"organisation,omitempty"`
	Error         string   `json:"error,omitempty"`
}

var mxProviderPatterns = []struct {
	provider string
	pattern  string
}{
	{"Microsoft", ".protection.outlook.com"},
	{"Google", ".google.com"},
	{"Mimecast", ".mimecast.com"},
	{"Proofpoint", ".pphosted.com"},
	{"Barracuda", ".barracudanetworks.com"},
	{"Sophos", ".sophos.com"},
	{"Cisco/IronPort", "ironport"},
	{"Zivver", "zivver"},
	{"KPN", ".kpnmail.nl"},
	{"Ziggo", ".ziggo.nl"},
}

var spfIncludeProviders = []struct {
	provider string
	pattern  string
}{
	{"Microsoft", "spf.protection.outlook.com"},
	{"Google", "_spf.google.com"},
	{"Mailchimp", "servers.mcsv.net"},
	{"SendGrid", "sendgrid.net"},
	{"Zendesk", "mail.zendesk.com"},
	{"Mimecast", "mimecast.com"},
	{"Proofpoint", "pphosted.com"},
	{"Sophos", "sophos.com"},
	{"Cisco/IronPort", "ironport"},
}

var asnMap = map[string]string{
	"AS16509": "Amazon",
	"AS13335": "Cloudflare",
	"AS15169": "Google",
	"AS8075":  "Microsoft",
	"AS20940": "Akamai",
	"AS3356":  "Lumen",
}

func main() {
	var (
		fileArg = flag.String("f", "", "Path to file with one domain per line")
		workers = flag.Int("workers", 20, "Number of concurrent workers for file input")
		timeout = flag.Duration("timeout", 2*time.Second, "Per-lookup timeout")
		jsonOut = flag.Bool("json", false, "Output as JSON")
	)
	flag.Parse()

	var domains []string
	if *fileArg != "" {
		d, err := readDomainsFromFile(*fileArg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read domains file: %v\n", err)
			os.Exit(1)
		}
		domains = d
	} else {
		if flag.NArg() < 1 {
			fmt.Fprintln(os.Stderr, "Usage: mail-lens [-f domains.txt] [--workers 20] [--json] <domain>")
			os.Exit(2)
		}
		domain := normaliseDomain(flag.Arg(0))
		if domain != "" {
			domains = []string{domain}
		}
	}

	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "No valid domains to analyse")
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Analysing %d domain(s)...\n", len(domains))

	var results []Result
	if *fileArg != "" {
		results = runWorkerPool(domains, *workers, *timeout)
	} else {
		results = []Result{analyseDomain(domains[0], *timeout)}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].Domain < results[j].Domain })

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	printTable(results)
}

func readDomainsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]struct{}{}
	out := make([]string, 0)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d := normaliseDomain(line)
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normaliseDomain(in string) string {
	d := strings.TrimSpace(strings.ToLower(in))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimSuffix(d, "/")
	if idx := strings.Index(d, "/"); idx != -1 {
		d = d[:idx]
	}
	if d == "" {
		return ""
	}
	return d
}

func runWorkerPool(domains []string, workerCount int, timeout time.Duration) []Result {
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan string)
	results := make(chan Result, len(domains))
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- analyseDomain(d, timeout)
			}
		}()
	}

	go func() {
		for _, d := range domains {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := make([]Result, 0, len(domains))
	for r := range results {
		out = append(out, r)
	}
	return out
}

func analyseDomain(domain string, timeout time.Duration) Result {
	res := Result{Domain: domain, Provider: "Unknown", ASN: "Unknown", Organisation: "Unknown"}

	mxHosts, err := lookupMX(domain, timeout)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if len(mxHosts) == 0 {
		res.Error = "No MX records"
		return res
	}

	res.PrimaryMX = mxHosts[0]
	res.Provider = detectProviderFromMX(mxHosts)

	spfTxt := lookupSPF(domain, timeout)
	res.SecurityStack = detectSecurityStackFromSPF(spfTxt)

	if strings.EqualFold(res.Provider, "Unknown") || strings.EqualFold(res.Provider, "Internal") {
		asn, org := lookupASNFromMX(mxHosts[0], timeout)
		if asn != "" {
			res.ASN = asn
		}
		if org != "" {
			res.Organisation = org
		}
	}

	if res.Provider == "Unknown" && res.ASN != "Unknown" {
		if p, ok := asnMap[res.ASN]; ok {
			res.Provider = p
		}
	}

	return res
}

func lookupMX(domain string, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.Resolver{}
	mx, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}

	sort.Slice(mx, func(i, j int) bool {
		if mx[i].Pref == mx[j].Pref {
			return mx[i].Host < mx[j].Host
		}
		return mx[i].Pref < mx[j].Pref
	})

	hosts := make([]string, 0, len(mx))
	for _, r := range mx {
		h := strings.TrimSuffix(strings.ToLower(r.Host), ".")
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

func detectProviderFromMX(mxHosts []string) string {
	for _, host := range mxHosts {
		for _, p := range mxProviderPatterns {
			if strings.Contains(host, p.pattern) {
				return p.provider
			}
		}
	}
	return "Internal"
}

func lookupSPF(domain string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return ""
	}
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			return t
		}
	}
	return ""
}

func detectSecurityStackFromSPF(spf string) []string {
	if spf == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}

	lower := strings.ToLower(spf)
	tokens := strings.Fields(lower)
	for _, tok := range tokens {
		if !strings.HasPrefix(tok, "include:") {
			continue
		}
		inc := strings.TrimPrefix(tok, "include:")
		for _, p := range spfIncludeProviders {
			if strings.Contains(inc, p.pattern) {
				if _, ok := seen[p.provider]; !ok {
					seen[p.provider] = struct{}{}
					out = append(out, p.provider)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func lookupASNFromMX(mxHost string, timeout time.Duration) (asn string, org string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, mxHost)
	if err != nil || len(ips) == 0 {
		return "Unknown", "Unknown"
	}

	for _, ip := range ips {
		a, o := cymruLookup(ip.IP.String(), timeout)
		if a != "" {
			return a, o
		}
	}
	return "Unknown", "Unknown"
}

func cymruLookup(ip string, timeout time.Duration) (asn string, org string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return "", ""
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	query := fmt.Sprintf(" -v %s\n", ip)
	if _, err := conn.Write([]byte(query)); err != nil {
		return "", ""
	}

	sc := bufio.NewScanner(conn)
	lines := []string{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) < 2 {
		return "", ""
	}

	parts := strings.Split(lines[1], "|")
	if len(parts) < 7 {
		return "", ""
	}
	rawASN := strings.TrimSpace(parts[0])
	rawOrg := strings.TrimSpace(parts[6])
	if rawASN == "" {
		return "", ""
	}
	return "AS" + rawASN, rawOrg
}

func printTable(results []Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "Domain\tPrimary MX\tProvider\tSecurity Stack (SPF includes)\tASN\tOrganisation\tStatus")
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		stack := "-"
		if len(r.SecurityStack) > 0 {
			stack = strings.Join(r.SecurityStack, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			empty(r.Domain),
			empty(r.PrimaryMX),
			empty(r.Provider),
			stack,
			empty(r.ASN),
			empty(r.Organisation),
			status,
		)
	}
	_ = w.Flush()
}

func empty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
