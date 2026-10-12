// Package taintscan finds prompt-injection attempts and leaked secrets in
// text an AI agent is about to read: tool output, fetched pages, repo files.
// It is a detector only. Scanned content is data and is never interpreted.
package taintscan

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed rules/*.yaml
var embeddedRules embed.FS

var (
	categories = map[string]bool{"injection": true, "secret": true, "obfuscation": true}
	severities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	idPattern  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
)

// DefaultRules loads the rule set compiled into the binary.
func DefaultRules() ([]Rule, error) {
	sub, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		return nil, err
	}
	return loadRulesFS(sub)
}

// Rule is one detection rule loaded from YAML.
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Category    string   `yaml:"category"` // injection | secret | obfuscation
	Severity    string   `yaml:"severity"`
	Regex       string   `yaml:"regex"`
	Keywords    []string `yaml:"keywords"`    // cheap lower-case prefilter, any must appear
	MinEntropy  float64  `yaml:"min_entropy"` // Shannon bits/char for capture group 1 (or whole match)
	Description string   `yaml:"description"`
	re          *regexp.Regexp
}

// LoadRules reads every *.yaml in dir and validates it. A missing directory
// or an empty rule set is an error: scanning with no rules would silently
// report everything as clean.
func LoadRules(dir string) ([]Rule, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}
	return loadRulesFS(os.DirFS(dir))
}

func loadRulesFS(fsys fs.FS) ([]Rule, error) {
	paths, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var out []Rule
	seen := map[string]bool{}
	for _, p := range paths {
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		var file struct {
			Rules []Rule `yaml:"rules"`
		}
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&file); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, r := range file.Rules {
			if err := r.validate(); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", p, r.ID, err)
			}
			if seen[r.ID] {
				return nil, fmt.Errorf("%s: duplicate rule id %q", p, r.ID)
			}
			seen[r.ID] = true
			r.re = regexp.MustCompile(r.Regex)
			for i := range r.Keywords {
				r.Keywords[i] = strings.ToLower(r.Keywords[i])
			}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no rules found")
	}
	return out, nil
}

func (r Rule) validate() error {
	if !idPattern.MatchString(r.ID) {
		return fmt.Errorf("id must be lowercase-kebab-case")
	}
	if !categories[r.Category] {
		return fmt.Errorf("category %q must be injection, secret or obfuscation", r.Category)
	}
	if !severities[r.Severity] {
		return fmt.Errorf("severity %q must be low, medium, high or critical", r.Severity)
	}
	if r.Regex == "" {
		return fmt.Errorf("regex is required")
	}
	if _, err := regexp.Compile(r.Regex); err != nil {
		return err
	}
	if r.MinEntropy < 0 || r.MinEntropy > 8 {
		return fmt.Errorf("min_entropy must be between 0 and 8")
	}
	return nil
}

// Entropy is Shannon entropy in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]float64{}
	n := 0.0
	for _, r := range s {
		freq[r]++
		n++
	}
	h := 0.0
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}
