package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/youwannahackme/vulncat/classifier"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

const Banner = colorBold + colorCyan + `
   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗  █████╗ ████████╗
   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝
   ██║   ██║██║   ██║██║     ██╔██╗ ██║██║      ███████║   ██║   
   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║      ██╔══██║   ██║   
    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗ ██║  ██║   ██║   
     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ` + colorReset + `

   ` + colorBold + colorWhite + `⚡ ADVANCED VULNERABILITY SURFACE CLASSIFIER & RECON ENGINE ⚡` + colorReset + `
   ` + colorCyan + `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━` + colorReset + `
   ` + colorBold + `  • Author     :` + colorReset + colorYellow + ` whoami_404` + colorReset + `
   ` + colorBold + `  • Repository :` + colorReset + colorCyan + ` github.com/youwannahackme/vulncat` + colorReset + `
   ` + colorCyan + `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━` + colorReset + `
`

func getCategoryColor(cat string) string {
	switch cat {
	case "sqli", "lfi", "rce", "ssti":
		return colorRed
	case "ssrf", "nosqli":
		return colorPurple
	case "xss", "idor", "redirect", "cors", "jwt":
		return colorCyan
	default:
		return colorYellow
	}
}

func init() {
	initConsole()
}

// DedupKey represents the host, path, category, and parameter name to limit matching redundancy
type DedupKey struct {
	Host     string
	Path     string
	Category string
	Param    string
}

// getDedupKey constructs the comparison key from a URL, category, and parameter
func getDedupKey(rawURL string, category string, param string) (DedupKey, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return DedupKey{}, err
	}
	return DedupKey{
		Host:     parsed.Host,
		Path:     parsed.Path,
		Category: category,
		Param:    strings.ToLower(param),
	}, nil
}

// Job represents a URL to be classified
type Job struct {
	URL string
}

// Result holds the classification outcomes or any parsing errors
type Result struct {
	URL  string
	Hits classifier.URLClassification
	Err  error
}

// ReportEntry defines the JSON output schema
type ReportEntry struct {
	URL        string                       `json:"url"`
	Categories classifier.URLClassification `json:"categories"`
}

// CategoryConfidencePair maps a URL to its classification confidence for sorting
type CategoryConfidencePair struct {
	Confidence int
	URL        string
}

func main() {
	var (
		urlFlag           string
		listFlag          string
		outputFlag        string
		minConfidenceFlag int
		maxPerPatternFlag int
		concurrencyFlag   int
		silentFlag        bool
		jsonlFlag         bool

		sqliFlag     bool
		xssFlag      bool
		ssrfFlag     bool
		lfiFlag      bool
		rceFlag      bool
		idorFlag     bool
		redirectFlag bool
		sstiFlag     bool
		nosqliFlag   bool
		corsFlag     bool
		jwtFlag      bool
		privescFlag  bool
		xxeFlag      bool
		protoFlag    bool
		categoryFlag string
	)

	// Bind both short and long flag names for a professional CLI UX
	flag.StringVar(&urlFlag, "u", "", "Single URL to classify")
	flag.StringVar(&urlFlag, "url", "", "Single URL to classify")

	flag.StringVar(&listFlag, "l", "", "Path to urls.txt (one URL per line, or '-' for stdin)")
	flag.StringVar(&listFlag, "list", "", "Path to urls.txt (one URL per line, or '-' for stdin)")

	flag.StringVar(&outputFlag, "o", "urlclass_out", "Output directory")
	flag.StringVar(&outputFlag, "output", "urlclass_out", "Output directory")

	flag.IntVar(&minConfidenceFlag, "min-confidence", 40, "Minimum confidence (0-100) to tag a category")
	flag.IntVar(&maxPerPatternFlag, "max-per-pattern", 5, "Max URLs kept per (host, path, category, param) group")

	flag.IntVar(&concurrencyFlag, "c", 20, "Number of concurrent workers")
	flag.IntVar(&concurrencyFlag, "concurrency", 20, "Number of concurrent workers")

	flag.BoolVar(&silentFlag, "s", false, "Silent mode (print matches to stdout, suppress banner and statistics)")
	flag.BoolVar(&silentFlag, "silent", false, "Silent mode (print matches to stdout, suppress banner and statistics)")

	flag.BoolVar(&jsonlFlag, "jsonl", false, "Output results in JSON Lines format instead of standard JSON")

	flag.BoolVar(&sqliFlag, "sqli", false, "Scan only for SQL injection vulnerability surface")
	flag.BoolVar(&xssFlag, "xss", false, "Scan only for Cross-Site Scripting vulnerability surface")
	flag.BoolVar(&ssrfFlag, "ssrf", false, "Scan only for Server-Side Request Forgery vulnerability surface")
	flag.BoolVar(&lfiFlag, "lfi", false, "Scan only for Local File Inclusion vulnerability surface")
	flag.BoolVar(&rceFlag, "rce", false, "Scan only for Remote Code Execution vulnerability surface")
	flag.BoolVar(&idorFlag, "idor", false, "Scan only for Insecure Direct Object Reference vulnerability surface")
	flag.BoolVar(&redirectFlag, "redirect", false, "Scan only for Open Redirect vulnerability surface")
	flag.BoolVar(&sstiFlag, "ssti", false, "Scan only for Server-Side Template Injection vulnerability surface")
	flag.BoolVar(&nosqliFlag, "nosqli", false, "Scan only for NoSQL Injection vulnerability surface")
	flag.BoolVar(&corsFlag, "cors", false, "Scan only for CORS Misconfiguration vulnerability surface")
	flag.BoolVar(&jwtFlag, "jwt", false, "Scan only for JWT Injection vulnerability surface")
	flag.BoolVar(&privescFlag, "privesc", false, "Scan only for Privilege Escalation vulnerability surface")
	flag.BoolVar(&xxeFlag, "xxe", false, "Scan only for XML External Entity vulnerability surface")
	flag.BoolVar(&protoFlag, "proto", false, "Scan only for Prototype Pollution vulnerability surface")
	flag.StringVar(&categoryFlag, "cat", "", "Comma-separated list of categories to scan for (e.g. sqli,xss)")

	flag.Usage = func() {
		if !silentFlag {
			fmt.Fprint(os.Stderr, Banner)
		}
		fmt.Fprintf(os.Stderr, "%sDESCRIPTION:%s\n", colorBold+colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  Vulncat is a high-speed, multi-dimensional vulnerability surface classifier.\n")
		fmt.Fprintf(os.Stderr, "  It analyzes URL parameters and path structures to identify quantitative heuristic sinks across\n")
		fmt.Fprintf(os.Stderr, "  14 vulnerability categories: %sSQLi, XSS, SSRF, LFI, RCE, IDOR, Redirect, SSTI, NoSQLi, CORS, JWT, PrivEsc, XXE, Proto%s.\n\n", colorBold+colorWhite, colorReset)

		fmt.Fprintf(os.Stderr, "%sUSAGE:%s\n", colorBold+colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  vulncat [options]\n\n")

		fmt.Fprintf(os.Stderr, "%sTARGETING OPTIONS:%s\n", colorBold+colorCyan, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-u, -url <string>%s       Single target URL to classify\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-l, -list <string>%s      Path to URL list file (one URL per line, or '-' for stdin)\n\n", colorGreen, colorReset)

		fmt.Fprintf(os.Stderr, "%sEXECUTION & TUNING:%s\n", colorBold+colorCyan, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-c, -concurrency <int>%s  Number of concurrent workers %s(default: 20)%s\n", colorGreen, colorReset, colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-min-confidence <int>%s   Minimum confidence threshold (0-100) to emit a match %s(default: 40)%s\n", colorGreen, colorReset, colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-max-per-pattern <int>%s  Max URLs kept per unique (host, path, category, param) signature %s(default: 5)%s\n\n", colorGreen, colorReset, colorYellow, colorReset)

		fmt.Fprintf(os.Stderr, "%sVULNERABILITY CATEGORY FILTERS:%s\n", colorBold+colorPurple, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-sqli%s                   Scan only for SQL Injection (SQLi) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-xss%s                    Scan only for Cross-Site Scripting (XSS) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-ssrf%s                   Scan only for Server-Side Request Forgery (SSRF) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-lfi%s                    Scan only for Local File Inclusion / Traversal (LFI) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-rce%s                    Scan only for Remote Code Execution (RCE) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-idor%s                   Scan only for Insecure Direct Object Reference (IDOR) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-redirect%s               Scan only for Open Redirect surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-ssti%s                   Scan only for Server-Side Template Injection (SSTI) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-nosqli%s                 Scan only for NoSQL Injection surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-cors%s                   Scan only for CORS Misconfiguration surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-jwt%s                    Scan only for JSON Web Token (JWT) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-privesc%s                Scan only for Privilege Escalation surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-xxe%s                    Scan only for XML External Entity (XXE) surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-proto%s                  Scan only for Prototype Pollution surface\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-cat <string>%s           Comma-separated list of categories to scan %s(e.g. sqli,xss,proto)%s\n\n", colorGreen, colorReset, colorYellow, colorReset)

		fmt.Fprintf(os.Stderr, "%sOUTPUT & FORMATTING:%s\n", colorBold+colorCyan, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-o, -output <string>%s    Output directory for category hits and full JSON report %s(default: \"urlclass_out\")%s\n", colorGreen, colorReset, colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-jsonl%s                  Output structured JSON Lines (.jsonl) stream to stdout\n", colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "  %s-s, -silent%s             Silent mode (suppress banner, logs, and statistics; print only matching URLs)\n\n", colorGreen, colorReset)

		fmt.Fprintf(os.Stderr, "%sEXAMPLES:%s\n", colorBold+colorYellow, colorReset)
		fmt.Fprintf(os.Stderr, "  %s# Classify a single target URL and output details:%s\n", colorPurple, colorReset)
		fmt.Fprintf(os.Stderr, "  vulncat -u \"https://target.com/search?q=test&id=5\"\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Scan a massive list of URLs with 50 concurrent workers and save to results/:%s\n", colorPurple, colorReset)
		fmt.Fprintf(os.Stderr, "  vulncat -l urls.txt -c 50 -o results/\n\n")
		fmt.Fprintf(os.Stderr, "  %s# Pipe recon URLs from stdin and filter only for SQLi & XSS in JSON Lines format:%s\n", colorPurple, colorReset)
		fmt.Fprintf(os.Stderr, "  cat recon.txt | vulncat -silent -jsonl -cat sqli,xss\n\n")
	}

	flag.Parse()

	if concurrencyFlag <= 0 {
		concurrencyFlag = 20
	}
	if maxPerPatternFlag <= 0 {
		maxPerPatternFlag = 5
	}
	if minConfidenceFlag < 0 {
		minConfidenceFlag = 0
	} else if minConfidenceFlag > 100 {
		minConfidenceFlag = 100
	}

	if !silentFlag {
		fmt.Fprint(os.Stderr, Banner)
	}

	// Parse and build the active categories filter
	activeCategories := make(map[string]bool)
	if sqliFlag {
		activeCategories["sqli"] = true
	}
	if xssFlag {
		activeCategories["xss"] = true
	}
	if ssrfFlag {
		activeCategories["ssrf"] = true
	}
	if lfiFlag {
		activeCategories["lfi"] = true
	}
	if rceFlag {
		activeCategories["rce"] = true
	}
	if idorFlag {
		activeCategories["idor"] = true
	}
	if redirectFlag {
		activeCategories["redirect"] = true
	}
	if sstiFlag {
		activeCategories["ssti"] = true
	}
	if nosqliFlag {
		activeCategories["nosqli"] = true
	}
	if corsFlag {
		activeCategories["cors"] = true
	}
	if jwtFlag {
		activeCategories["jwt"] = true
	}
	if privescFlag {
		activeCategories["privesc"] = true
	}
	if xxeFlag {
		activeCategories["xxe"] = true
	}
	if protoFlag {
		activeCategories["proto"] = true
	}

	if categoryFlag != "" {
		parts := strings.Split(categoryFlag, ",")
		for _, p := range parts {
			trimmed := strings.TrimSpace(strings.ToLower(p))
			if trimmed != "" {
				activeCategories[trimmed] = true
			}
		}
	}

	// Default to all categories if no filters are supplied
	if len(activeCategories) == 0 {
		for _, cat := range classifier.Categories {
			activeCategories[cat.Name] = true
		}
	}

	// Detect if stdin has piped data
	var hasPipeInput bool
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		hasPipeInput = true
	}

	// Validate that there is an input source
	if urlFlag == "" && listFlag == "" && !hasPipeInput {
		fmt.Fprintf(os.Stderr, "[-] Error: must specify a single URL (-u), a list file (-l), or pipe input via stdin.\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Setup streaming pipeline channels
	jobs := make(chan string, 1000)
	results := make(chan Result, 1000)

	var totalInputCount int64

	// Start reader goroutine
	go func() {
		defer close(jobs)
		if urlFlag != "" {
			atomic.AddInt64(&totalInputCount, 1)
			jobs <- strings.TrimSpace(urlFlag)
			return
		}

		var scanner *bufio.Scanner
		if listFlag == "-" || (listFlag == "" && hasPipeInput) {
			scanner = bufio.NewScanner(os.Stdin)
		} else {
			file, err := os.Open(listFlag)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error opening file %s: %v\n", listFlag, err)
				os.Exit(1)
			}
			defer file.Close()
			scanner = bufio.NewScanner(file)
		}
		const maxBuf = 10 * 1024 * 1024
		buf := make([]byte, maxBuf)
		scanner.Buffer(buf, maxBuf)

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				atomic.AddInt64(&totalInputCount, 1)
				jobs <- line
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error reading input stream: %v\n", err)
		}
	}()

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < concurrencyFlag; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				hits, err := classifier.ClassifyURL(u, minConfidenceFlag, activeCategories)
				results <- Result{URL: u, Hits: hits, Err: err}
			}
		}()
	}

	// Close results channel when workers complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Aggregator variables
	categoryURLs := make(map[string][]CategoryConfidencePair)
	seenGroups := make(map[DedupKey]int)
	report := []ReportEntry{}
	var skippedCount int64

	// Collect results from pipeline
	for res := range results {
		if res.Err != nil {
			atomic.AddInt64(&skippedCount, 1)
			continue
		}
		if len(res.Hits) == 0 {
			continue
		}

		entry := ReportEntry{
			URL:        res.URL,
			Categories: make(classifier.URLClassification),
		}

		hasNewHit := false
		for catName, info := range res.Hits {
			key, err := getDedupKey(res.URL, catName, info.Param)
			if err != nil {
				continue
			}
			if seenGroups[key] >= maxPerPatternFlag {
				continue
			}
			seenGroups[key]++
			hasNewHit = true
			categoryURLs[catName] = append(categoryURLs[catName], CategoryConfidencePair{
				Confidence: info.Confidence,
				URL:        res.URL,
			})
			entry.Categories[catName] = info
		}

		if hasNewHit && len(entry.Categories) > 0 {
			report = append(report, entry)

			if silentFlag {
				if jsonlFlag {
					data, err := json.Marshal(entry)
					if err == nil {
						fmt.Println(string(data))
					}
				} else {
					fmt.Println(res.URL)
				}
			} else {
				if jsonlFlag {
					data, err := json.Marshal(entry)
					if err == nil {
						fmt.Println(string(data))
					}
				} else {
					var catNames []string
					for catName := range entry.Categories {
						catNames = append(catNames, catName)
					}
					sort.Strings(catNames)

					var tags []string
					for _, catName := range catNames {
						info := entry.Categories[catName]
						tagColor := getCategoryColor(catName)
						tags = append(tags, fmt.Sprintf("%s%s:%d%s", tagColor, catName, info.Confidence, colorReset))
					}
					fmt.Printf("[%s] %s%s%s\n", strings.Join(tags, "]["), colorBold+colorWhite, res.URL, colorReset)
				}
			}
		}
	}

	// Ensure output directory exists
	err := os.MkdirAll(outputFlag, 0755)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	// Write category specific output files (sorted by confidence descending)
	for _, cat := range classifier.Categories {
		entries, exists := categoryURLs[cat.Name]
		if !exists || len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			if entries[i].Confidence == entries[j].Confidence {
				return entries[i].URL < entries[j].URL
			}
			return entries[i].Confidence > entries[j].Confidence
		})

		outfilePath := filepath.Join(outputFlag, cat.Name+".txt")
		outFile, err := os.Create(outfilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error creating file %s: %v\n", outfilePath, err)
			continue
		}

		writer := bufio.NewWriter(outFile)
		for _, entry := range entries {
			_, _ = writer.WriteString(entry.URL + "\n")
		}
		_ = writer.Flush()
		_ = outFile.Close()
	}

	// Write full JSON/JSONL report file
	var repPath string
	if jsonlFlag {
		repPath = filepath.Join(outputFlag, "report.jsonl")
		reportFile, err := os.Create(repPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error creating report file: %v\n", err)
		} else {
			writer := bufio.NewWriter(reportFile)
			for _, entry := range report {
				data, err := json.Marshal(entry)
				if err == nil {
					_, _ = writer.WriteString(string(data) + "\n")
				}
			}
			_ = writer.Flush()
			_ = reportFile.Close()
		}
	} else {
		repPath = filepath.Join(outputFlag, "report.json")
		reportFile, err := os.Create(repPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Error creating report file: %v\n", err)
		} else {
			encoder := json.NewEncoder(reportFile)
			encoder.SetIndent("", "  ")
			err = encoder.Encode(report)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Error writing JSON report: %v\n", err)
			}
			_ = reportFile.Close()
		}
	}

	// Print summary report (only if not running in silent mode)
	if !silentFlag {
		fmt.Printf("\n%s[+] Processed %d URLs, skipped %d malformed%s\n", colorBold, atomic.LoadInt64(&totalInputCount), atomic.LoadInt64(&skippedCount), colorReset)
		fmt.Printf("%s[+] %d URLs tagged with at least one category%s\n", colorBold, len(report), colorReset)
		for _, cat := range classifier.Categories {
			count := len(categoryURLs[cat.Name])
			txtPath := filepath.Join(outputFlag, cat.Name+".txt")
			tagColor := getCategoryColor(cat.Name)
			fmt.Printf("    %s%-6s%s: %5d -> %s\n", tagColor, cat.Name, colorReset, count, txtPath)
		}
		fmt.Printf("%s[+] Full per-URL breakdown (matched param + reason): %s%s\n", colorGreen, repPath, colorReset)
	}
}
