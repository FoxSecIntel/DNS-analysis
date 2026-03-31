package main

import (
	"bufio"
	"context"
	"encoding/csv"
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
	Domain              string   `json:"domain"`
	PrimaryMX           string   `json:"primary_mx,omitempty"`
	Provider            string   `json:"provider,omitempty"`
	SecurityStack       []string `json:"security_stack,omitempty"`
	ASN                 string   `json:"asn,omitempty"`
	Organisation        string   `json:"organisation,omitempty"`
	SecurityGateway     string   `json:"security_gateway,omitempty"`
	MailServer          string   `json:"mail_server,omitempty"`
	SPFLookupCount      int      `json:"spf_lookup_count"`
	SPFRFCViolation     bool     `json:"spf_rfc_violation"`
	SPFFlattenedAuthors []string `json:"spf_flattened_authorised,omitempty"`
	DMARCPolicy         string   `json:"dmarc_policy,omitempty"`
	DMARCSubPolicy      string   `json:"dmarc_sub_policy,omitempty"`
	DMARCStrength       string   `json:"dmarc_strength,omitempty"`
	MonitoringVendor    string   `json:"monitoring_vendor,omitempty"`
	MTASTSEnabled       bool     `json:"mta_sts_enabled"`
	SMTPTLSEnabled      bool     `json:"smtp_tls_reporting_enabled"`
	Error               string   `json:"error,omitempty"`
}

var mxProviderPatterns = []struct {
	provider string
	pattern  string
}{
	{"Microsoft 365", ".messaging.microsoft.com"},
	{"Microsoft", ".protection.outlook.com"},
	{"Google", ".google.com"},
	{"Mimecast", ".mimecast.com"},
	{"Proofpoint", ".pphosted.com"},
	{"Barracuda", ".barracudanetworks.com"},
	{"Trend Micro", ".trendmicro.com"},
	{"Sophos", ".sophos.com"},
	{"Cisco/IronPort", "ironport"},
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
}

var asnMap = map[string]string{
	"AS16509": "Amazon",
	"AS13335": "Cloudflare",
	"AS15169": "Google",
	"AS8075":  "Microsoft",
	"AS20940": "Akamai",
	"AS3356":  "Lumen",
}

var dmarcVendorMap = map[string]string{
	"agari.com":      "Agari",
	"dmarcian.com":   "dmarcian",
	"ondmarc.com":    "OnDMARC",
	"valimail.com":   "Valimail",
	"proofpoint.com": "Proofpoint",
}

func main() {
	var (
		fileArg   = flag.String("f", "", "Path to file with one domain per line")
		workers   = flag.Int("workers", 20, "Number of concurrent workers for file input")
		timeout   = flag.Duration("timeout", 2*time.Second, "Per-lookup timeout")
		jsonOut   = flag.Bool("json", false, "Output as JSON")
		outputArg = flag.String("output", "table", "Output format: table, json, csv, html")
		mEgg      = flag.Bool("m", false, "") // intentionally undocumented
		author    = flag.Bool("a", false, "Show author and repository details")
	)
	flag.Parse()

	if *author {
		fmt.Println("Author: FoxSecIntel")
		fmt.Println("Repository: https://github.com/FoxSecIntel/DNS-analysis")
		fmt.Println("Tool: mail-lens-go")
		return
	}
	if *mEgg {
		fmt.Println("Victory is not winning for ourselves, but for others. - The Mandalorian")
		return
	}

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
			fmt.Fprintln(os.Stderr, "Usage: mail-lens [-f domains.txt] [--workers 20] [--json] [--output table|json|csv|html] <domain>")
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

	out := strings.ToLower(strings.TrimSpace(*outputArg))
	if *jsonOut {
		out = "json"
	}

	switch out {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	case "csv":
		emitCSV(results)
	case "html":
		emitHTML(results)
	default:
		printTable(results)
	}
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
	res := Result{Domain: domain, Provider: "Unknown", ASN: "Unknown", Organisation: "Unknown", DMARCStrength: "Unknown"}

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
	res.SecurityGateway = detectSecurityGateway(mxHosts)

	spfEval := evaluateSPF(domain, timeout)
	res.SPFLookupCount = spfEval.LookupCount
	res.SPFRFCViolation = spfEval.LookupCount > 10
	res.SPFFlattenedAuthors = spfEval.Flattened
	res.SecurityStack = spfEval.Providers

	dmarc := evaluateDMARC(domain, timeout)
	res.DMARCPolicy = dmarc.Policy
	res.DMARCSubPolicy = dmarc.SubPolicy
	res.DMARCStrength = dmarc.Strength
	res.MonitoringVendor = dmarc.Vendor

	res.MTASTSEnabled = hasTXT("_mta-sts."+domain, timeout)
	res.SMTPTLSEnabled = hasTXT("_smtp._tls."+domain, timeout)

	res.MailServer = detectSMTPBanner(res.PrimaryMX, 3*time.Second)

	asn, org := lookupASNFromMX(res.PrimaryMX, timeout)
	if asn != "" {
		res.ASN = asn
	}
	if org != "" {
		res.Organisation = org
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

func detectSecurityGateway(mxHosts []string) string {
	for _, host := range mxHosts {
		h := strings.ToLower(host)
		switch {
		case strings.HasSuffix(h, ".pphosted.com"):
			return "Proofpoint"
		case strings.HasSuffix(h, ".mimecast.com"):
			return "Mimecast"
		case strings.HasSuffix(h, ".messaging.microsoft.com"):
			return "Microsoft 365"
		case strings.HasSuffix(h, ".barracudanetworks.com"):
			return "Barracuda"
		case strings.HasSuffix(h, ".trendmicro.com"):
			return "Trend Micro"
		}
	}
	return "Unknown"
}

type spfState struct {
	LookupCount int
	Flattened   []string
	Providers   []string
	seenDomains map[string]struct{}
	seenAuth    map[string]struct{}
	seenProv    map[string]struct{}
}

func evaluateSPF(domain string, timeout time.Duration) spfState {
	st := spfState{seenDomains: map[string]struct{}{}, seenAuth: map[string]struct{}{}, seenProv: map[string]struct{}{}}
	resolveSPFDomain(domain, timeout, &st)
	sort.Strings(st.Flattened)
	sort.Strings(st.Providers)
	return st
}

func resolveSPFDomain(domain string, timeout time.Duration, st *spfState) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return
	}
	if _, ok := st.seenDomains[domain]; ok {
		return
	}
	st.seenDomains[domain] = struct{}{}

	txt := lookupSPF(domain, timeout)
	if txt == "" {
		return
	}
	for _, p := range spfIncludeProviders {
		if strings.Contains(strings.ToLower(txt), p.pattern) {
			if _, ok := st.seenProv[p.provider]; !ok {
				st.seenProv[p.provider] = struct{}{}
				st.Providers = append(st.Providers, p.provider)
			}
		}
	}
	toks := strings.Fields(strings.ToLower(txt))
	for _, tok := range toks {
		switch {
		case strings.HasPrefix(tok, "include:"):
			st.LookupCount++
			resolveSPFDomain(strings.TrimPrefix(tok, "include:"), timeout, st)
		case strings.HasPrefix(tok, "redirect="):
			st.LookupCount++
			resolveSPFDomain(strings.TrimPrefix(tok, "redirect="), timeout, st)
		case strings.HasPrefix(tok, "ip4:"):
			addAuth(st, strings.TrimPrefix(tok, "ip4:"))
		case strings.HasPrefix(tok, "ip6:"):
			addAuth(st, strings.TrimPrefix(tok, "ip6:"))
		case tok == "a" || strings.HasPrefix(tok, "a:"):
			st.LookupCount++
		case tok == "mx" || strings.HasPrefix(tok, "mx:"):
			st.LookupCount++
		}
	}
}

func addAuth(st *spfState, v string) {
	if v == "" {
		return
	}
	if _, ok := st.seenAuth[v]; ok {
		return
	}
	st.seenAuth[v] = struct{}{}
	st.Flattened = append(st.Flattened, v)
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

type dmarcEval struct {
	Policy    string
	SubPolicy string
	Strength  string
	Vendor    string
}

func evaluateDMARC(domain string, timeout time.Duration) dmarcEval {
	out := dmarcEval{Strength: "Weak"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return out
	}
	var rec string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			rec = t
			break
		}
	}
	if rec == "" {
		return out
	}
	parts := strings.Split(rec, ";")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "p":
			out.Policy = strings.ToLower(v)
		case "sp":
			out.SubPolicy = strings.ToLower(v)
		case "rua", "ruf":
			if out.Vendor == "" {
				out.Vendor = detectMonitoringVendor(v)
			}
		}
	}
	if out.Policy == "reject" || out.Policy == "quarantine" {
		out.Strength = "Strong"
	}
	return out
}

func detectMonitoringVendor(v string) string {
	items := strings.Split(v, ",")
	for _, item := range items {
		item = strings.TrimSpace(strings.ToLower(item))
		if strings.HasPrefix(item, "mailto:") {
			item = strings.TrimPrefix(item, "mailto:")
		}
		if at := strings.LastIndex(item, "@"); at >= 0 {
			d := item[at+1:]
			for key, name := range dmarcVendorMap {
				if strings.Contains(d, key) {
					return name
				}
			}
		}
	}
	return "Unknown"
}

func hasTXT(name string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolver := net.Resolver{}
	txts, err := resolver.LookupTXT(ctx, name)
	return err == nil && len(txts) > 0
}

func detectSMTPBanner(mxHost string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(mxHost, "25"))
	if err != nil {
		return "Unknown"
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return "Unknown"
	}
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "microsoft esmtp") || strings.Contains(lower, "exchange"):
		return "Exchange"
	case strings.Contains(lower, "postfix"):
		return "Postfix"
	case strings.Contains(lower, "sendmail"):
		return "Sendmail"
	case strings.Contains(lower, "exim"):
		return "Exim"
	case strings.Contains(lower, "cisco"):
		return "Cisco SMTP"
	default:
		return strings.TrimSpace(line)
	}
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
	var dialer net.Dialer
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
	fmt.Fprintln(w, "Domain\tPrimary MX\tGateway\tMail Server\tDMARC\tMonitoring\tSPF Lookups\tSPF RFC Violation\tMTA-STS\tSMTP TLS-RPT\tASN\tOrganisation\tStatus")
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%t\t%t\t%t\t%s\t%s\t%s\n",
			empty(r.Domain), empty(r.PrimaryMX), empty(r.SecurityGateway), empty(r.MailServer),
			empty(r.DMARCStrength), empty(r.MonitoringVendor), r.SPFLookupCount, r.SPFRFCViolation,
			r.MTASTSEnabled, r.SMTPTLSEnabled, empty(r.ASN), empty(r.Organisation), status)
	}
	_ = w.Flush()
}

func emitCSV(results []Result) {
	w := csv.NewWriter(os.Stdout)
	_ = w.Write([]string{"domain", "primary_mx", "security_gateway", "mail_server", "dmarc_strength", "monitoring_vendor", "spf_lookup_count", "spf_rfc_violation", "spf_flattened_authorised", "mta_sts_enabled", "smtp_tls_reporting_enabled", "asn", "organisation", "status"})
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		_ = w.Write([]string{r.Domain, r.PrimaryMX, r.SecurityGateway, r.MailServer, r.DMARCStrength, r.MonitoringVendor, fmt.Sprintf("%d", r.SPFLookupCount), fmt.Sprintf("%t", r.SPFRFCViolation), strings.Join(r.SPFFlattenedAuthors, ";"), fmt.Sprintf("%t", r.MTASTSEnabled), fmt.Sprintf("%t", r.SMTPTLSEnabled), r.ASN, r.Organisation, status})
	}
	w.Flush()
}

func emitHTML(results []Result) {
	fmt.Println("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>mail-lens</title><style>body{font-family:Arial,sans-serif;margin:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;font-size:12px;text-align:left}th{background:#f2f2f2}</style></head><body>")
	fmt.Println("<h1>mail-lens attribution report</h1><table><thead><tr><th>Domain</th><th>Primary MX</th><th>Gateway</th><th>Mail Server</th><th>DMARC</th><th>Monitoring</th><th>SPF Lookups</th><th>RFC Violation</th><th>MTA-STS</th><th>TLS-RPT</th><th>ASN</th><th>Organisation</th><th>Status</th></tr></thead><tbody>")
	for _, r := range results {
		status := "OK"
		if r.Error != "" {
			status = r.Error
		}
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%t</td><td>%t</td><td>%t</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			htmlEscape(empty(r.Domain)), htmlEscape(empty(r.PrimaryMX)), htmlEscape(empty(r.SecurityGateway)), htmlEscape(empty(r.MailServer)), htmlEscape(empty(r.DMARCStrength)), htmlEscape(empty(r.MonitoringVendor)), r.SPFLookupCount, r.SPFRFCViolation, r.MTASTSEnabled, r.SMTPTLSEnabled, htmlEscape(empty(r.ASN)), htmlEscape(empty(r.Organisation)), htmlEscape(status))
	}
	fmt.Println("</tbody></table></body></html>")
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}

func empty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
