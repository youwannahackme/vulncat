package classifier

import (
	"testing"
)

func TestClassifyURL(t *testing.T) {
	tests := []struct {
		name             string
		url              string
		minConfidence    int
		activeCategories map[string]bool
		expectedCategory string
		expectedMinConf  int
	}{
		{
			name: "SQLi numeric parameter",
			url:  "https://example.com/item.php?id=123",
			minConfidence: 40,
			activeCategories: map[string]bool{"sqli": true},
			expectedCategory: "sqli",
			expectedMinConf:  70, // strong param (40) + value shape numeric (30)
		},
		{
			name: "XSS text query parameter",
			url:  "https://example.com/search?q=testquery",
			minConfidence: 40,
			activeCategories: map[string]bool{"xss": true},
			expectedCategory: "xss",
			expectedMinConf:  70, // strong param (40) + value shape text (30)
		},
		{
			name: "SSRF URL parameter",
			url:  "https://example.com/proxy?url=https://internal.metadata.google.com/computeMetadata/v1/",
			minConfidence: 40,
			activeCategories: map[string]bool{"ssrf": true},
			expectedCategory: "ssrf",
			expectedMinConf:  70, // strong param (40) + value shape url (30)
		},
		{
			name: "LFI path parameter",
			url:  "https://example.com/view?file=../../../../etc/passwd",
			minConfidence: 40,
			activeCategories: map[string]bool{"lfi": true},
			expectedCategory: "lfi",
			expectedMinConf:  70, // strong param (40) + value shape path (30)
		},
		{
			name: "RCE command parameter",
			url:  "https://example.com/run?cmd=whoami",
			minConfidence: 40,
			activeCategories: map[string]bool{"rce": true},
			expectedCategory: "rce",
			expectedMinConf:  70, // strong param (40) + value shape command (30)
		},
		{
			name: "IDOR numeric ID parameter",
			url:  "https://example.com/account?invoice_id=456",
			minConfidence: 40,
			activeCategories: map[string]bool{"idor": true},
			expectedCategory: "idor",
			expectedMinConf:  90, // strong param (40) + value shape numeric (30) + IDOR numeric bonus (20)
		},
		{
			name: "Redirect target parameter",
			url:  "https://example.com/login?redirect=https://attacker.com",
			minConfidence: 40,
			activeCategories: map[string]bool{"redirect": true},
			expectedCategory: "redirect",
			expectedMinConf:  70, // strong param (40) + value shape redirect (30)
		},
		{
			name: "SSTI template parameter",
			url:  "https://example.com/render?template={{7*7}}",
			minConfidence: 40,
			activeCategories: map[string]bool{"ssti": true},
			expectedCategory: "ssti",
			expectedMinConf:  70, // strong param (40) + value shape template (30)
		},
		{
			name: "NoSQLi operator parameter",
			url:  "https://example.com/login?user[$ne]=admin",
			minConfidence: 40,
			activeCategories: map[string]bool{"nosqli": true},
			expectedCategory: "nosqli",
			expectedMinConf:  70, // strong param (40) + value shape nosql (30)
		},
		{
			name: "CORS origin parameter",
			url:  "https://example.com/api?origin=https://attacker.com",
			minConfidence: 40,
			activeCategories: map[string]bool{"cors": true},
			expectedCategory: "cors",
			expectedMinConf:  70, // strong param (40) + value shape url (30)
		},
		{
			name: "JWT token parameter",
			url:  "https://example.com/api?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			minConfidence: 40,
			activeCategories: map[string]bool{"jwt": true},
			expectedCategory: "jwt",
			expectedMinConf:  70, // strong param (40) + value shape jwt (30)
		},
		{
			name: "PrivEsc admin parameter",
			url:  "https://example.com/profile?role=admin",
			minConfidence: 40,
			activeCategories: map[string]bool{"privesc": true},
			expectedCategory: "privesc",
			expectedMinConf:  70, // strong param (40) + value shape role/boolean (30)
		},
		{
			name: "XXE payload parameter",
			url:  "https://example.com/api?xml=<?xml+version=\"1.0\"?><!DOCTYPE+foo+SYSTEM+...>",
			minConfidence: 40,
			activeCategories: map[string]bool{"xxe": true},
			expectedCategory: "xxe",
			expectedMinConf:  70, // strong param (40) + value shape xml (30)
		},
		{
			name: "Proto pollution parameter name",
			url:  "https://example.com/config?__proto__[polluted]=true",
			minConfidence: 40,
			activeCategories: map[string]bool{"proto": true},
			expectedCategory: "proto",
			expectedMinConf:  70, // strong param key (40) + value shape json/boolean (30)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ClassifyURL(tt.url, tt.minConfidence, tt.activeCategories)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res == nil {
				t.Fatalf("expected classification result, got nil")
			}
			result, ok := res[tt.expectedCategory]
			if !ok {
				t.Fatalf("expected category %s not found in results: %v", tt.expectedCategory, res)
			}
			if result.Confidence < tt.expectedMinConf {
				t.Errorf("expected confidence >= %d, got %d", tt.expectedMinConf, result.Confidence)
			}
		})
	}
}

func TestClassifyURLNoiseFiltering(t *testing.T) {
	active := map[string]bool{}
	for _, c := range Categories {
		active[c.Name] = true
	}

	// 1. Static extensions should be skipped
	res, err := ClassifyURL("https://example.com/static/style.css?id=123", 40, active)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("expected static file style.css to be filtered out, but got: %v", res)
	}

	// 2. Tracking parameters should be ignored
	res, err = ClassifyURL("https://example.com/search?fbclid=xyz", 40, active)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Errorf("expected tracking parameter fbclid to be filtered out, but got: %v", res)
	}
}
