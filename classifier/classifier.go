package classifier

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Global tracking parameters and static extensions to ignore
var TrackingParams = map[string]bool{
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"fbclid":       true,
	"gclid":        true,
	"msclkid":      true,
	"mc_cid":       true,
	"mc_eid":       true,
	"_ga":          true,
	"_gid":         true,
	"igshid":       true,
	"yclid":        true,
	"dclid":        true,
	"twclid":       true,
	"ttclid":       true,
}

var StaticExtensions = map[string]bool{
	".css":   true,
	".js":    true,
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".svg":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".ico":   true,
	".map":   true,
	".mp4":   true,
	".webp":  true,
	".avif":  true,
}

// Pre-compiled regular expressions for shape checks
var (
	reURL2 = regexp.MustCompile(`(?i)^[a-z0-9.-]+\.[a-z]{2,}(/|$)`)
	reJWT  = regexp.MustCompile(`(?i)^[a-z0-9_-]+\.[a-z0-9_-]+\.[a-z0-9_-]+$`)
)

// Helper word lists
var commandWords = map[string]bool{
	"ping": true, "ls": true, "whoami": true, "id": true, "cat": true,
}

var pathExtensions = map[string]bool{
	".php":   true,
	".asp":   true,
	".aspx":  true,
	".jsp":   true,
	".txt":   true,
	".log":   true,
	".conf":  true,
	".ini":   true,
	".env":   true,
	".xml":   true,
	".json":  true,
	".html":  true,
	".htm":   true,
	".bak":   true,
	".yml":   true,
	".yaml":  true,
}

// unquote is a forgiving path-unescape wrapper (similar to urllib.parse.unquote)
func unquote(v string) string {
	if !strings.Contains(v, "%") {
		return v
	}
	decoded, err := url.PathUnescape(v)
	if err != nil {
		return v
	}
	return decoded
}

// Value shape heuristic check functions
func isNumeric(v string) bool {
	if len(v) == 0 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < '0' || v[i] > '9' {
			return false
		}
	}
	return true
}

func isURLLike(v string) bool {
	dv := unquote(v)
	dvLower := strings.ToLower(dv)
	if strings.HasPrefix(dvLower, "http://") || strings.HasPrefix(dvLower, "https://") || strings.HasPrefix(dv, "//") {
		return true
	}
	if reURL2.MatchString(dv) && strings.Contains(dv, "/") {
		return true
	}
	return false
}

func isPathLike(v string) bool {
	dv := unquote(v)
	if strings.Contains(dv, "../") || strings.Contains(strings.ToLower(v), "..%2f") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(dv))
	if pathExtensions[ext] {
		return true
	}
	if strings.HasPrefix(dv, "/") || strings.HasPrefix(dv, "\\") {
		return true
	}
	return false
}

func hasThreeConsecutiveLetters(s string) bool {
	count := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			count++
			if count >= 3 {
				return true
			}
		} else {
			count = 0
		}
	}
	return false
}

func isTextLike(v string) bool {
	dv := unquote(v)
	return hasThreeConsecutiveLetters(dv) && !isNumeric(dv)
}

func isCommandLike(v string) bool {
	dv := unquote(v)
	if strings.ContainsAny(dv, ";&|`$") {
		return true
	}
	return commandWords[strings.ToLower(dv)]
}

func isTemplateLike(v string) bool {
	dv := unquote(v)
	return strings.Contains(dv, "${") || strings.Contains(dv, "{{") || strings.Contains(dv, "<%") || strings.Contains(dv, "#{")
}

func isNoSQLLike(v string) bool {
	dv := unquote(v)
	return strings.Contains(dv, "$ne") || strings.Contains(dv, "$gt") || strings.Contains(dv, "$lt") || strings.Contains(dv, "$in") || strings.Contains(dv, "$regex") || strings.Contains(dv, "$where") || strings.Contains(dv, "$eq")
}

func isJWTLike(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) > 7 && strings.EqualFold(v[:7], "bearer ") {
		v = strings.TrimSpace(v[7:])
	}
	if strings.Count(v, ".") != 2 {
		return false
	}
	return reJWT.MatchString(v)
}

func isRedirectValue(v string) bool {
	return isURLLike(v) || isPathLike(v)
}

func isRoleOrBoolean(v string) bool {
	dv := strings.ToLower(unquote(v))
	if dv == "true" || dv == "false" || dv == "0" || dv == "1" {
		return true
	}
	roles := map[string]bool{
		"admin": true, "user": true, "guest": true, "member": true,
		"editor": true, "manager": true, "root": true, "moderator": true,
		"staff": true, "superuser": true,
	}
	return roles[dv]
}

func isXMLLike(v string) bool {
	dv := strings.TrimSpace(unquote(v))
	if strings.HasPrefix(dv, "<") && strings.HasSuffix(dv, ">") {
		return true
	}
	dvLower := strings.ToLower(dv)
	return strings.Contains(dvLower, "<?xml") || strings.Contains(dvLower, "<!entity") || strings.Contains(dvLower, "<!doctype")
}

func isJSONLike(v string) bool {
	dv := strings.TrimSpace(unquote(v))
	return (strings.HasPrefix(dv, "{") && strings.HasSuffix(dv, "}")) || (strings.HasPrefix(dv, "[") && strings.HasSuffix(dv, "]"))
}

// Category configuration
type CategoryConfig struct {
	Name         string
	StrongParams map[string]bool
	WeakParams   map[string]bool
	ValueShape   func(string) bool
	PathContext  []string
}

var Categories = []CategoryConfig{
	{
		Name: "sqli",
		StrongParams: map[string]bool{
			"id": true, "user_id": true, "uid": true, "pid": true, "product_id": true, "cat_id": true,
			"category": true, "item_id": true, "order_id": true, "invoice_id": true,
			"article_id": true, "post_id": true, "news_id": true, "report_id": true,
			"sort": true, "filter": true, "select": true,
		},
		WeakParams: map[string]bool{
			"page": true, "view": true, "type": true, "ref": true, "num": true,
		},
		ValueShape: isNumeric,
		PathContext: []string{
			"product", "item", "order", "report", "account",
			"user", "admin", "invoice", "article", "news",
		},
	},
	{
		Name: "xss",
		StrongParams: map[string]bool{
			"q": true, "query": true, "search": true, "s": true, "keyword": true, "keywords": true,
			"term": true, "message": true, "comment": true, "msg": true, "feedback": true,
			"content": true, "text": true, "title": true, "desc": true, "description": true,
			"name": true, "subject": true, "html": true,
		},
		WeakParams: map[string]bool{
			"redirect_msg": true, "callback": true, "jsonp": true, "value": true, "input": true,
		},
		ValueShape: isTextLike,
		PathContext: []string{
			"search", "comment", "contact", "feedback", "review",
			"post", "blog", "profile",
		},
	},
	{
		Name: "ssrf",
		StrongParams: map[string]bool{
			"url": true, "uri": true, "dest": true, "destination": true, "redirect": true,
			"return": true, "returnurl": true, "next": true, "continue": true, "target": true,
			"host": true, "domain": true, "callback": true, "webhook": true, "feed": true,
			"src": true, "source": true, "proxy": true, "fetch": true, "image_url": true,
			"avatar_url": true, "link": true, "out": true,
		},
		WeakParams: map[string]bool{
			"data": true, "path": true, "load": true, "site": true,
		},
		ValueShape: isURLLike,
		PathContext: []string{
			"proxy", "fetch", "image", "download", "import",
			"webhook", "callback", "share", "preview",
		},
	},
	{
		Name: "lfi",
		StrongParams: map[string]bool{
			"file": true, "filename": true, "path": true, "filepath": true, "page": true,
			"template": true, "doc": true, "document": true, "folder": true, "dir": true,
			"root": true, "load": true, "read": true, "view": true, "include": true, "inc": true,
			"locale": true, "lang": true, "conf": true, "config": true, "style": true,
		},
		WeakParams: map[string]bool{
			"module": true, "name": true, "type": true,
		},
		ValueShape: isPathLike,
		PathContext: []string{
			"download", "view", "read", "include", "template",
			"locale", "static", "asset", "cms",
		},
	},
	{
		Name: "rce",
		StrongParams: map[string]bool{
			"cmd": true, "command": true, "exec": true, "execute": true, "run": true, "ping": true,
			"shell": true, "system": true, "func": true, "function": true, "action": true,
			"do": true, "code": true, "eval": true,
		},
		WeakParams: map[string]bool{
			"query": true, "task": true, "job": true,
		},
		ValueShape: isCommandLike,
		PathContext: []string{
			"cmd", "exec", "tool", "ping", "diagnostic", "debug",
			"admin", "console", "system",
		},
	},
	{
		Name: "idor",
		StrongParams: map[string]bool{
			"id": true, "user_id": true, "uid": true, "account_id": true, "order_id": true,
			"invoice_id": true, "profile_id": true, "doc_id": true, "customer_id": true,
			"member_id": true, "ticket_id": true, "record_id": true,
		},
		WeakParams: map[string]bool{
			"num": true, "no": true, "ref": true, "key": true,
		},
		ValueShape: isNumeric,
		PathContext: []string{
			"account", "profile", "order", "invoice", "user",
			"ticket", "document", "record", "api",
		},
	},
	{
		Name: "redirect",
		StrongParams: map[string]bool{
			"redirect": true, "redirect_to": true, "url": true, "go": true, "return": true,
			"returnurl": true, "return_to": true, "next": true, "continue": true, "window": true,
			"u": true, "r": true, "target": true, "out": true, "dest": true, "destination": true,
		},
		WeakParams: map[string]bool{
			"link": true, "site": true, "path": true, "host": true, "domain": true,
		},
		ValueShape: isRedirectValue,
		PathContext: []string{
			"login", "logout", "oauth", "redirect", "signin", "signup", "external", "out",
		},
	},
	{
		Name: "ssti",
		StrongParams: map[string]bool{
			"template": true, "layout": true, "theme": true, "view": true, "page": true,
			"render": true, "name": true, "id": true, "message": true, "content": true,
		},
		WeakParams: map[string]bool{
			"text": true, "value": true, "q": true, "query": true,
		},
		ValueShape: isTemplateLike,
		PathContext: []string{
			"template", "render", "view", "email", "pdf", "invoice", "preview",
		},
	},
	{
		Name: "nosqli",
		StrongParams: map[string]bool{
			"filter": true, "query": true, "search": true, "user": true, "username": true,
			"password": true, "where": true, "find": true, "match": true, "db": true, "id": true,
		},
		WeakParams: map[string]bool{
			"q": true, "params": true, "data": true, "criteria": true,
		},
		ValueShape: isNoSQLLike,
		PathContext: []string{
			"api", "search", "filter", "db", "query", "mongodb", "nosql",
		},
	},
	{
		Name: "cors",
		StrongParams: map[string]bool{
			"origin": true, "cors": true, "header": true, "allowed": true, "credentials": true, "request": true,
		},
		WeakParams: map[string]bool{
			"host": true, "site": true, "url": true,
		},
		ValueShape: isURLLike,
		PathContext: []string{
			"api", "cors", "auth", "login", "oauth", "credential",
		},
	},
	{
		Name: "jwt",
		StrongParams: map[string]bool{
			"token": true, "jwt": true, "auth": true, "authorization": true, "session": true, "cookie": true, "bearer": true,
		},
		WeakParams: map[string]bool{
			"key": true, "id": true, "user": true,
		},
		ValueShape: isJWTLike,
		PathContext: []string{
			"auth", "api", "login", "jwt", "token", "session",
		},
	},
	{
		Name: "privesc",
		StrongParams: map[string]bool{
			"admin": true, "role": true, "is_admin": true, "isadmin": true, "privilege": true,
			"user_type": true, "group": true, "access_level": true, "role_id": true,
			"is_staff": true, "superuser": true,
		},
		WeakParams: map[string]bool{
			"status": true, "type": true, "level": true, "group_id": true,
		},
		ValueShape: isRoleOrBoolean,
		PathContext: []string{
			"admin", "user", "role", "profile", "setting", "update", "manage",
		},
	},
	{
		Name: "xxe",
		StrongParams: map[string]bool{
			"xml": true, "xml_data": true, "xmldoc": true, "doc": true, "data": true,
			"payload": true, "request": true, "input": true,
		},
		WeakParams: map[string]bool{
			"file": true, "content": true, "body": true,
		},
		ValueShape: isXMLLike,
		PathContext: []string{
			"xml", "soap", "api", "endpoint", "parse", "upload", "import",
		},
	},
	{
		Name: "proto",
		StrongParams: map[string]bool{
			"__proto__": true, "constructor[prototype]": true, "constructor.prototype": true,
		},
		WeakParams: map[string]bool{
			"config": true, "settings": true, "options": true, "query": true,
		},
		ValueShape: isJSONLike,
		PathContext: []string{
			"api", "config", "parse", "merge", "extend", "json",
		},
	},
}

var CategoriesMap = make(map[string]CategoryConfig)

func init() {
	for _, cat := range Categories {
		CategoriesMap[cat.Name] = cat
	}
}

// Scoring constants
const (
	StrongParamScore = 40
	WeakParamScore   = 20
	ValueShapeBonus  = 30
	PathContextBonus = 10
	IdorNumericBonus = 20
)

func cleanParamName(name string) string {
	idx := strings.Index(name, "[")
	if idx != -1 {
		return name[:idx]
	}
	return name
}

// ClassifyParam scores a parameter based on a category config
func ClassifyParam(category string, paramName string, paramValue string, pathLower string) (int, []string) {
	cfg, ok := CategoriesMap[category]
	if !ok {
		return 0, nil
	}
	paramLower := strings.ToLower(paramName)
	score := 0
	var reasons []string

	// Clean parameter name for dictionary lookup (e.g. filter[username] -> filter)
	cleanName := cleanParamName(paramLower)

	if cfg.StrongParams[cleanName] {
		score += StrongParamScore
		reasons = append(reasons, fmt.Sprintf("param '%s' is a known %s sink", paramName, category))
	} else if cfg.WeakParams[cleanName] {
		score += WeakParamScore
		reasons = append(reasons, fmt.Sprintf("param '%s' is a weak %s indicator", paramName, category))
	} else {
		// Special case for NoSQLi: if the param name itself contains a NoSQL operator
		if category == "nosqli" && (strings.Contains(paramLower, "[$ne]") || strings.Contains(paramLower, "[$gt]") || strings.Contains(paramLower, "[$lt]") || strings.Contains(paramLower, "[$in]") || strings.Contains(paramLower, "[$regex]")) {
			score += StrongParamScore
			reasons = append(reasons, fmt.Sprintf("param '%s' contains NoSQL operator", paramName))
		} else if category == "proto" && (strings.Contains(paramLower, "__proto__") || strings.Contains(paramLower, "constructor[prototype]") || strings.Contains(paramLower, "constructor.prototype")) {
			// Special case for Prototype Pollution parameter names
			score += StrongParamScore
			reasons = append(reasons, fmt.Sprintf("param '%s' contains prototype pollution key", paramName))
		} else {
			return 0, nil
		}
	}

	if paramValue != "" && cfg.ValueShape(paramValue) {
		score += ValueShapeBonus
		reasons = append(reasons, fmt.Sprintf("value shape matches %s pattern", category))
	}

	hasPathContext := false
	for _, kw := range cfg.PathContext {
		if strings.Contains(pathLower, kw) {
			hasPathContext = true
			break
		}
	}
	if hasPathContext {
		score += PathContextBonus
		reasons = append(reasons, fmt.Sprintf("endpoint path suggests %s context", category))
	}

	if category == "idor" && isNumeric(paramValue) {
		score += IdorNumericBonus
		reasons = append(reasons, "sequential numeric identifier")
	}

	if score > 100 {
		score = 100
	}
	return score, reasons
}

// CategoryResult stores the evaluation for a matched category
type CategoryResult struct {
	Confidence int      `json:"confidence"`
	Param      string   `json:"param"`
	Reasons    []string `json:"reasons"`
}

// URLClassification maps categories to their results
type URLClassification map[string]CategoryResult

// parseQsl parses query parameters without replacing '+' with space,
// matching Python's urllib.parse.parse_qsl behavior.
func parseQsl(query string) [][2]string {
	var result [][2]string
	if query == "" {
		return result
	}
	parts := strings.Split(query, "&")
	for _, part := range parts {
		if part == "" {
			continue
		}
		var key, val string
		eqIdx := strings.Index(part, "=")
		if eqIdx == -1 {
			key = part
			val = ""
		} else {
			key = part[:eqIdx]
			val = part[eqIdx+1:]
		}

		keyDec, err := url.PathUnescape(key)
		if err != nil {
			keyDec = key
		}
		valDec, err := url.PathUnescape(val)
		if err != nil {
			valDec = val
		}
		result = append(result, [2]string{keyDec, valDec})
	}
	return result
}

// analyzePathSegments analyzes REST API URL path segments for parameter context (like IDOR/LFI)
func analyzePathSegments(parsedPath string) [][2]string {
	var inferredParams [][2]string

	parts := strings.Split(parsedPath, "/")
	var segments []string
	for _, p := range parts {
		if p != "" {
			segments = append(segments, p)
		}
	}

	for i, seg := range segments {
		// Case 1: Numeric identifier (potential IDOR / SQLi)
		if isNumeric(seg) {
			paramName := "path_id"
			if i > 0 {
				parent := segments[i-1]
				// Convert plural to singular for common API conventions (e.g. users -> user_id)
				if strings.HasSuffix(parent, "s") && len(parent) > 1 {
					paramName = parent[:len(parent)-1] + "_id"
				} else {
					paramName = parent + "_id"
				}
			}
			inferredParams = append(inferredParams, [2]string{paramName, seg})
		}

		// Case 2: Traversal or sensitive extensions in path segment (potential LFI / Directory Traversal)
		lowerSeg := strings.ToLower(seg)
		hasTraversal := strings.Contains(lowerSeg, "..") || strings.Contains(lowerSeg, "%2f")
		ext := strings.ToLower(filepath.Ext(seg))

		if hasTraversal || pathExtensions[ext] {
			paramValue := seg
			if hasTraversal && i < len(segments) {
				paramValue = strings.Join(segments[i:], "/")
			}

			paramName := "file"
			if pathExtensions[ext] {
				paramName = "path"
			}
			inferredParams = append(inferredParams, [2]string{paramName, paramValue})
		}
	}
	return inferredParams
}

// getRawPath extracts the raw uncleaned path from a URL to retain dot-dot-slash segments
func getRawPath(rawURL string) string {
	u := rawURL
	if idx := strings.Index(u, "#"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, "?"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	} else {
		u = strings.TrimPrefix(u, "//")
	}
	if idx := strings.Index(u, "/"); idx != -1 {
		return u[idx:]
	}
	return ""
}

// ClassifyURL runs classification heuristics across all categories on a given URL
func ClassifyURL(rawURL string, minConfidence int, activeCategories map[string]bool) (URLClassification, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	pathLower := strings.ToLower(parsed.Path)
	ext := strings.ToLower(filepath.Ext(parsed.Path))

	// Allow checking paths even if extension matches static, UNLESS there's no path segments.
	if StaticExtensions[ext] {
		return nil, nil
	}

	params := parseQsl(parsed.RawQuery)
	var filteredParams [][2]string
	for _, pair := range params {
		if !TrackingParams[strings.ToLower(pair[0])] {
			filteredParams = append(filteredParams, pair)
		}
	}

	// Analyze REST API path parameters and append them (using uncleaned raw path for LFI)
	inferredPathParams := analyzePathSegments(getRawPath(rawURL))
	filteredParams = append(filteredParams, inferredPathParams...)

	if len(filteredParams) == 0 {
		return nil, nil
	}

	results := make(URLClassification)
	for _, pair := range filteredParams {
		paramName := pair[0]
		paramValue := pair[1]

		for _, cat := range Categories {
			if !activeCategories[cat.Name] {
				continue
			}
			score, reasons := ClassifyParam(cat.Name, paramName, paramValue, pathLower)
			if score >= minConfidence {
				existing, exists := results[cat.Name]
				if !exists || score > existing.Confidence {
					results[cat.Name] = CategoryResult{
						Confidence: score,
						Param:      paramName,
						Reasons:    reasons,
					}
				}
			}
		}
	}

	if len(results) == 0 {
		return nil, nil
	}
	return results, nil
}
