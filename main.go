package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
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

const Banner = colorCyan + `
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗  █████╗ ████████╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║      ███████║   ██║   
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║      ██╔══██║   ██║   
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗ ██║  ██║   ██║   
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ` + colorReset + `

             Vulnerability Surface Classifier
                   Author: ` + colorYellow + `whoami_404` + colorReset + `
         Repository: ` + colorBlue + `github.com/youwannahackme` + colorReset + `
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
	if runtime.GOOS == "windows" {
		// Use lazy-loaded kernel32.dll to dynamically enable Virtual Terminal processing.
		// This avoids compilation errors on non-Windows systems where syscall.SetConsoleMode is undefined.
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		setConsoleMode := kernel32.NewProc("SetConsoleMode")
		getConsoleMode := kernel32.NewProc("GetConsoleMode")

		handleOut, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
		if err == nil {
			var mode uint32
			r, _, errCall := getConsoleMode.Call(uintptr(handleOut), uintptr(unsafe.Pointer(&mode)))
			if r != 0 && errCall == nil || errCall.Error() == "The operation completed successfully." {
				mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
				_, _, _ = setConsoleMode.Call(uintptr(handleOut), uintptr(mode))
			}
		}

		handleErr, err := syscall.GetStdHandle(syscall.STD_ERROR_HANDLE)
		if err == nil {
			var mode uint32
			r, _, errCall := getConsoleMode.Call(uintptr(handleErr), uintptr(unsafe.Pointer(&mode)))
			if r != 0 && errCall == nil || errCall.Error() == "The operation completed successfully." {
				mode |= 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
				_, _, _ = setConsoleMode.Call(uintptr(handleErr), uintptr(mode))
			}
		}
	}
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
	Hits URLClassification
	Err  error
}

// ReportEntry defines the JSON output schema
type ReportEntry struct {
	URL        string            `json:"url"`
	Categories URLClassification `json:"categories"`
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
	flag.StringVar(&categoryFlag, "cat", "", "Comma-separated list of categories to scan for (e.g. sqli,xss)")

	flag.Usage = func() {
		if !silentFlag {
			fmt.Fprint(os.Stderr, Banner)
		}
		fmt.Fprint(os.Stderr, "\nDescription:\n")
		fmt.Fprint(os.Stderr, "  Vulncat is a high-performance vulnerability-surface URL classifier.\n")
		fmt.Fprint(os.Stderr, "  It scans query parameters and path segments for heuristics indicating XSS, SQLi, SSRF, LFI, RCE, IDOR, Redirect, SSTI, NoSQLi, CORS, and JWT.\n\n")

		fmt.Fprint(os.Stderr, "Usage:\n")
		fmt.Fprint(os.Stderr, "  vulncat [options]\n\n")

		fmt.Fprint(os.Stderr, "Targeting Options:\n")
		fmt.Fprint(os.Stderr, "  -u, -url <string>       Single URL to classify\n")
		fmt.Fprint(os.Stderr, "  -l, -list <string>      Path to list file (one URL per line, or '-' for stdin)\n\n")

		fmt.Fprint(os.Stderr, "Optimization & Execution:\n")
		fmt.Fprint(os.Stderr, "  -c, -concurrency <int>  Number of concurrent workers (default: 20)\n")
		fmt.Fprint(os.Stderr, "  -min-confidence <int>   Minimum confidence score (0-100) to report (default: 40)\n")
		fmt.Fprint(os.Stderr, "  -max-per-pattern <int>  Max URLs to report per (host, path, category, param) (default: 5)\n\n")

		fmt.Fprint(os.Stderr, "Vulnerability Scan Filters:\n")
		fmt.Fprint(os.Stderr, "  -sqli                   Scan only for SQL Injection surface\n")
		fmt.Fprint(os.Stderr, "  -xss                    Scan only for Cross-Site Scripting surface\n")
		fmt.Fprint(os.Stderr, "  -ssrf                   Scan only for Server-Side Request Forgery surface\n")
		fmt.Fprint(os.Stderr, "  -lfi                    Scan only for Local File Inclusion surface\n")
		fmt.Fprint(os.Stderr, "  -rce                    Scan only for Remote Code Execution surface\n")
		fmt.Fprint(os.Stderr, "  -idor                   Scan only for Insecure Direct Object Reference surface\n")
		fmt.Fprint(os.Stderr, "  -redirect               Scan only for Open Redirect surface\n")
		fmt.Fprint(os.Stderr, "  -ssti                   Scan only for Server-Side Template Injection surface\n")
		fmt.Fprint(os.Stderr, "  -nosqli                 Scan only for NoSQL Injection surface\n")
		fmt.Fprint(os.Stderr, "  -cors                   Scan only for CORS Misconfiguration surface\n")
		fmt.Fprint(os.Stderr, "  -jwt                    Scan only for JWT surface\n")
		fmt.Fprint(os.Stderr, "  -cat <string>           Comma-separated list of categories to scan (e.g. sqli,xss)\n\n")

		fmt.Fprint(os.Stderr, "Output Options:\n")
		fmt.Fprint(os.Stderr, "  -o, -output <string>    Output directory for logs and hits (default: \"urlclass_out\")\n")
		fmt.Fprint(os.Stderr, "  -jsonl                  Output results in JSON Lines (.jsonl) format\n")
		fmt.Fprint(os.Stderr, "  -s, -silent             Silent mode (suppress banner, logs, and stats; only print matching URLs)\n\n")

		fmt.Fprint(os.Stderr, "Examples:\n")
		fmt.Fprint(os.Stderr, "  vulncat -u \"https://target.com/search?q=test&id=5\"\n")
		fmt.Fprint(os.Stderr, "  vulncat -l urls.txt -o results/\n")
		fmt.Fprint(os.Stderr, "  cat urls.txt | vulncat -silent -sqli\n")
	}

	flag.Parse()

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
		for _, cat := range Categories {
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
				hits, err := ClassifyURL(u, minConfidenceFlag, activeCategories)
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
	var report []ReportEntry
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
			Categories: make(URLClassification),
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
	for _, cat := range Categories {
		entries, exists := categoryURLs[cat.Name]
		if !exists || len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
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
		for _, cat := range Categories {
			count := len(categoryURLs[cat.Name])
			txtPath := filepath.Join(outputFlag, cat.Name+".txt")
			tagColor := getCategoryColor(cat.Name)
			fmt.Printf("    %s%-6s%s: %5d -> %s\n", tagColor, cat.Name, colorReset, count, txtPath)
		}
		fmt.Printf("%s[+] Full per-URL breakdown (matched param + reason): %s%s\n", colorGreen, repPath, colorReset)
	}
}
