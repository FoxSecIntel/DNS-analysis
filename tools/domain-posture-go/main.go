package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	whois "github.com/likexian/whois"
)

const perDomainTimeout = 8 * time.Second

type Result struct {
	Domain              string   `json:"domain"`
	ARecords            []string `json:"a_records"`
	AAAARecords         []string `json:"aaaa_records"`
	HTTPSReachable      bool     `json:"https_reachable"`
	RedirectFinalURL    string   `json:"redirect_final_url,omitempty"`
	SecurityTxtStatus   int      `json:"security_txt_status"`
	SecurityTxtURL      string   `json:"security_txt_url"`
	StrictTransport     string   `json:"strict_transport_security,omitempty"`
	ContentSecurity     string   `json:"content_security_policy,omitempty"`
	XFrameOptions       string   `json:"x_frame_options,omitempty"`
	CertificateExpiry   string   `json:"certificate_expiry,omitempty"`
	CertDaysRemaining   int      `json:"cert_days_remaining"`
	DomainAgeDays       int      `json:"domain_age_days"`
	WhoisCreatedDateRaw string   `json:"whois_created_date_raw,omitempty"`
	Errors              []string `json:"errors,omitempty"`
}

func main() {
	var domainFlag string
	var fileFlag string
	var outputFlag string
	var jsonOut bool
	var mandalorian bool
	var author bool
	var concurrency int

	flag.StringVar(&domainFlag, "domain", "", "Single domain to analyse")
	flag.StringVar(&fileFlag, "file", "", "File containing newline-delimited domains")
	flag.StringVar(&outputFlag, "output", "table", "Output format: table, json, csv, html")
	flag.BoolVar(&jsonOut, "json", false, "Output as JSON")
	flag.BoolVar(&mandalorian, "m", false, "")
	flag.BoolVar(&author, "a", false, "Show author and repository details")
	flag.IntVar(&concurrency, "concurrency", 10, "Worker pool concurrency")

	cleanArgs, positionalDomain := preprocessArgs(os.Args[1:])
	if err := flag.CommandLine.Parse(cleanArgs); err != nil {
		log.Fatalf("Unable to parse arguments: %v", err)
	}

	if mandalorian {
		fmt.Println("Victory is not winning for ourselves, but for others. - The Mandalorian")
		return
	}
	if author {
		fmt.Println("Author: FoxSecIntel")
		fmt.Println("Repository: https://github.com/FoxSecIntel/DNS-analysis")
		fmt.Println("Tool: domain-posture-go")
		return
	}

	if domainFlag == "" && positionalDomain != "" {
		domainFlag = positionalDomain
	}

	if domainFlag == "" && fileFlag == "" {
		log.Fatal("Provide a domain via positional argument, --domain, or --file")
	}
	if concurrency < 1 {
		concurrency = 1
	}

	if jsonOut {
		outputFlag = "json"
	}
	outputFlag = strings.ToLower(strings.TrimSpace(outputFlag))
	if outputFlag != "table" && outputFlag != "json" && outputFlag != "csv" && outputFlag != "html" {
		log.Fatalf("Unsupported output format: %s", outputFlag)
	}

	domains, err := collectDomains(domainFlag, fileFlag)
	if err != nil {
		log.Fatalf("Unable to collect domains: %v", err)
	}
	if len(domains) == 0 {
		log.Fatal("No domains found to analyse")
	}

	results := runPool(domains, concurrency)

	switch outputFlag {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			log.Fatalf("Unable to encode JSON: %v", err)
		}
	case "csv":
		if err := printCSV(results); err != nil {
			log.Fatalf("Unable to render CSV: %v", err)
		}
	case "html":
		printHTML(results)
	default:
		printTable(results)
	}
}

func preprocessArgs(args []string) ([]string, string) {
	clean := make([]string, 0, len(args))
	positionalDomain := ""
	skipNext := false

	for i := 0; i < len(args); i++ {
		if skipNext {
			skipNext = false
			continue
		}
		a := args[i]
		if strings.HasPrefix(a, "-") {
			clean = append(clean, a)
			if (a == "--domain" || a == "-domain" || a == "--file" || a == "-file" || a == "--output" || a == "-output" || a == "--concurrency" || a == "-concurrency") && i+1 < len(args) {
				clean = append(clean, args[i+1])
				skipNext = true
			}
			continue
		}
		if positionalDomain == "" {
			positionalDomain = a
		} else {
			clean = append(clean, a)
		}
	}

	return clean, positionalDomain
}

func collectDomains(single string, filePath string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	appendDomain := func(v string) {
		d := normaliseDomain(v)
		if d == "" {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}

	appendDomain(single)

	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		s := bufio.NewScanner(f)
		for s.Scan() {
			appendDomain(s.Text())
		}
		if err := s.Err(); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func normaliseDomain(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimSuffix(v, "/")
	if strings.Contains(v, "/") {
		parts := strings.Split(v, "/")
		v = parts[0]
	}
	return v
}

func runPool(domains []string, concurrency int) []Result {
	jobs := make(chan string)
	results := make(chan Result)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- analyseDomain(d)
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

	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

func analyseDomain(domain string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), perDomainTimeout)
	defer cancel()

	r := Result{Domain: domain, SecurityTxtStatus: -1, CertDaysRemaining: -1, DomainAgeDays: -1}

	a, aaaa, err := resolveIP(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("dns: %v", err))
	}
	r.ARecords = a
	r.AAAARecords = aaaa

	httpsReach, finalURL, headers, err := checkHTTPS(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("https: %v", err))
	}
	r.HTTPSReachable = httpsReach
	r.RedirectFinalURL = finalURL
	r.StrictTransport = headers.Get("Strict-Transport-Security")
	r.ContentSecurity = headers.Get("Content-Security-Policy")
	r.XFrameOptions = headers.Get("X-Frame-Options")

	status, secURL, err := checkSecurityTxt(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("security.txt: %v", err))
	}
	r.SecurityTxtStatus = status
	r.SecurityTxtURL = secURL

	expiry, days, err := certificateExpiry(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("tls cert: %v", err))
	}
	r.CertificateExpiry = expiry
	r.CertDaysRemaining = days

	createdRaw, ageDays, err := whoisAge(ctx, domain)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("whois: %v", err))
	}
	r.WhoisCreatedDateRaw = createdRaw
	r.DomainAgeDays = ageDays

	return r
}

func resolveIP(ctx context.Context, domain string) ([]string, []string, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, nil, err
	}

	v4set := map[string]struct{}{}
	v6set := map[string]struct{}{}
	for _, ip := range ips {
		if ip.IP.To4() != nil {
			v4set[ip.IP.String()] = struct{}{}
		} else {
			v6set[ip.IP.String()] = struct{}{}
		}
	}

	v4 := setToSortedSlice(v4set)
	v6 := setToSortedSlice(v6set)
	return v4, v6, nil
}

func setToSortedSlice(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func checkHTTPS(ctx context.Context, domain string) (bool, string, http.Header, error) {
	u := "https://" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, "", nil, err
	}

	client := &http.Client{
		Timeout: perDomainTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", nil, err
	}
	defer resp.Body.Close()

	final := u
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}
	return true, final, resp.Header, nil
}

func checkSecurityTxt(ctx context.Context, domain string) (int, string, error) {
	u := "https://" + domain + "/.well-known/security.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return -1, u, err
	}
	client := &http.Client{Timeout: perDomainTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return -1, u, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, u, nil
}

func certificateExpiry(ctx context.Context, domain string) (string, int, error) {
	dialer := &net.Dialer{Timeout: perDomainTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{ServerName: domain})
	if err != nil {
		return "", -1, err
	}
	defer conn.Close()
	if err := conn.HandshakeContext(ctx); err != nil {
		return "", -1, err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", -1, errors.New("no peer certificate returned")
	}
	notAfter := state.PeerCertificates[0].NotAfter
	days := int(time.Until(notAfter).Hours() / 24)
	return notAfter.Format(time.RFC3339), days, nil
}

func whoisAge(ctx context.Context, domain string) (string, int, error) {
	type out struct {
		raw string
		err error
	}
	ch := make(chan out, 1)
	go func() {
		res, err := whois.Whois(domain)
		if err != nil {
			ch <- out{"", err}
			return
		}
		ch <- out{res, nil}
	}()

	select {
	case <-ctx.Done():
		return "", -1, ctx.Err()
	case v := <-ch:
		if v.err != nil {
			return "", -1, v.err
		}
		createdRaw, createdAt, err := extractCreatedDate(v.raw)
		if err != nil {
			return "", -1, err
		}
		ageDays := int(time.Since(createdAt).Hours() / 24)
		return createdRaw, ageDays, nil
	}
}

func extractCreatedDate(whoisText string) (string, time.Time, error) {
	patterns := []string{
		`(?im)^Creation Date:\s*(.+)$`,
		`(?im)^Created On:\s*(.+)$`,
		`(?im)^Registered On:\s*(.+)$`,
		`(?im)^Domain Registration Date:\s*(.+)$`,
		`(?im)^Registered:\s*(.+)$`,
	}

	var raw string
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		m := re.FindStringSubmatch(whoisText)
		if len(m) > 1 {
			raw = strings.TrimSpace(m[1])
			break
		}
	}
	if raw == "" {
		return "", time.Time{}, errors.New("unable to locate creation date in WHOIS")
	}

	clean := strings.TrimSpace(raw)
	clean = strings.Trim(clean, ".")

	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"02-Jan-2006 15:04:05 MST",
		"2006.01.02 15:04:05",
		"2006/01/02",
		"02/01/2006",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, clean); err == nil {
			return raw, t, nil
		}
	}

	// Attempt to parse if WHOIS includes trailing notes after date.
	parts := strings.Fields(clean)
	for i := len(parts); i >= 1; i-- {
		candidate := strings.Join(parts[:i], " ")
		for _, layout := range layouts {
			if t, err := time.Parse(layout, candidate); err == nil {
				return raw, t, nil
			}
		}
	}

	return raw, time.Time{}, fmt.Errorf("unsupported WHOIS date format: %q", raw)
}

func printTable(results []Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DOMAIN\tA\tAAAA\tHTTPS\tREDIRECT\tSEC.TXT\tHSTS\tCSP\tXFO\tCERT DAYS\tWHOIS AGE\tNOTES")
	for _, r := range results {
		notes := ""
		if len(r.Errors) > 0 {
			notes = strings.Join(r.Errors, " | ")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\t%d\t%s\t%s\t%s\t%d\t%d\t%s\n",
			r.Domain,
			joinOrDash(r.ARecords),
			joinOrDash(r.AAAARecords),
			r.HTTPSReachable,
			trimURL(r.RedirectFinalURL),
			r.SecurityTxtStatus,
			shortHeader(r.StrictTransport),
			shortHeader(r.ContentSecurity),
			shortHeader(r.XFrameOptions),
			r.CertDaysRemaining,
			r.DomainAgeDays,
			notes,
		)
	}
	_ = w.Flush()
}

func printCSV(results []Result) error {
	w := csv.NewWriter(os.Stdout)
	headers := []string{"domain", "a_records", "aaaa_records", "https_reachable", "redirect_final_url", "security_txt_status", "strict_transport_security", "content_security_policy", "x_frame_options", "certificate_expiry", "cert_days_remaining", "domain_age_days", "whois_created_date_raw", "errors"}
	if err := w.Write(headers); err != nil {
		return err
	}
	for _, r := range results {
		errLine := strings.Join(r.Errors, " | ")
		row := []string{
			r.Domain,
			joinOrDash(r.ARecords),
			joinOrDash(r.AAAARecords),
			fmt.Sprintf("%t", r.HTTPSReachable),
			r.RedirectFinalURL,
			fmt.Sprintf("%d", r.SecurityTxtStatus),
			r.StrictTransport,
			r.ContentSecurity,
			r.XFrameOptions,
			r.CertificateExpiry,
			fmt.Sprintf("%d", r.CertDaysRemaining),
			fmt.Sprintf("%d", r.DomainAgeDays),
			r.WhoisCreatedDateRaw,
			errLine,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func printHTML(results []Result) {
	fmt.Println("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>domain-posture</title><style>body{font-family:Arial,sans-serif;margin:16px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:6px 8px;font-size:12px;text-align:left}th{background:#f2f2f2}code{white-space:pre-wrap}</style></head><body>")
	fmt.Println("<h1>domain-posture report</h1>")
	fmt.Println("<table><thead><tr><th>Domain</th><th>A</th><th>AAAA</th><th>HTTPS</th><th>Redirect</th><th>security.txt</th><th>HSTS</th><th>CSP</th><th>XFO</th><th>Cert days</th><th>Whois age</th><th>Notes</th></tr></thead><tbody>")
	for _, r := range results {
		notes := strings.Join(r.Errors, " | ")
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%t</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td><code>%s</code></td></tr>\n",
			htmlEscape(r.Domain),
			htmlEscape(joinOrDash(r.ARecords)),
			htmlEscape(joinOrDash(r.AAAARecords)),
			r.HTTPSReachable,
			htmlEscape(r.RedirectFinalURL),
			r.SecurityTxtStatus,
			htmlEscape(r.StrictTransport),
			htmlEscape(r.ContentSecurity),
			htmlEscape(r.XFrameOptions),
			r.CertDaysRemaining,
			r.DomainAgeDays,
			htmlEscape(notes),
		)
	}
	fmt.Println("</tbody></table></body></html>")
}

func htmlEscape(v string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;", "'", "&#39;")
	return replacer.Replace(v)
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ",")
}

func shortHeader(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "-"
	}
	if len(v) > 48 {
		return v[:45] + "..."
	}
	return v
}

func trimURL(v string) string {
	if v == "" {
		return "-"
	}
	u, err := url.Parse(v)
	if err != nil {
		return v
	}
	out := u.Scheme + "://" + u.Host + u.Path
	if out == "://" {
		return v
	}
	if len(out) > 64 {
		return out[:61] + "..."
	}
	return out
}
