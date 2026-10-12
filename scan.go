package taintscan

import (
	"sort"
	"strings"
)

// Finding is one rule hit. Secrets are redacted; the raw value is never kept.
type Finding struct {
	RuleID   string `json:"rule"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Line     int    `json:"line"`
	Excerpt  string `json:"excerpt"`
}

const ignoreMarker = "taintscan:ignore"

// Options tunes a scan.
type Options struct {
	// HonorIgnore skips lines containing "taintscan:ignore". Off by default:
	// anyone who controls the scanned text can append the marker, so it must
	// only be enabled for content you author yourself, such as your own
	// documentation and test fixtures.
	HonorIgnore bool
}

// Scan applies rules to text. Inline ignore markers are NOT honored.
func Scan(rules []Rule, text string) []Finding { return ScanWith(rules, text, Options{}) }

type span struct{ start, end int }

// ScanWith applies rules to text with options.
func ScanWith(rules []Rule, text string, opt Options) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		if opt.HonorIgnore && strings.Contains(line, ignoreMarker) {
			continue
		}
		lower := strings.ToLower(line)
		var hits []Rule
		for _, r := range rules {
			if len(r.Keywords) > 0 && !anyContains(lower, r.Keywords) {
				continue
			}
			if ruleFires(r, line) {
				hits = append(hits, r)
			}
		}
		if len(hits) == 0 {
			continue
		}
		safe := redactLine(rules, lower, line)
		for _, r := range hits {
			out = append(out, Finding{r.ID, r.Category, r.Severity, i + 1, safe})
		}
	}
	return out
}

// ruleFires checks every match on the line, not just the first, so a benign
// low-entropy match cannot hide a real one later in the line.
func ruleFires(r Rule, line string) bool {
	for _, m := range r.re.FindAllStringSubmatch(line, -1) {
		val := m[0]
		if len(m) > 1 && m[1] != "" {
			val = m[1]
		}
		if r.MinEntropy == 0 || Entropy(val) >= r.MinEntropy {
			return true
		}
	}
	return false
}

// redactLine masks every match of every secret rule on the line (not only
// the rule that fired), then makes invisible characters visible. Every
// finding on a line shares this excerpt, so no finding can echo a secret.
func redactLine(rules []Rule, lower, line string) string {
	var spans []span
	for _, r := range rules {
		if r.Category != "secret" {
			continue
		}
		if len(r.Keywords) > 0 && !anyContains(lower, r.Keywords) {
			continue
		}
		for _, m := range r.re.FindAllStringSubmatchIndex(line, -1) {
			s, e := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 && m[3] > m[2] {
				s, e = m[2], m[3]
			}
			spans = append(spans, span{s, e})
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	pos := 0
	for _, sp := range spans {
		if sp.end <= pos {
			continue
		}
		if sp.start > pos {
			b.WriteString(line[pos:sp.start])
		}
		start := max(sp.start, pos)
		keep := 4
		if sp.end-start < 12 {
			keep = 1
		}
		b.WriteString(line[start : start+keep])
		b.WriteString("******")
		pos = sp.end
	}
	b.WriteString(line[pos:])
	var v strings.Builder
	for _, r := range b.String() {
		if isInvisible(r) {
			v.WriteString("<U+" + strings.ToUpper(strings.TrimLeft(hex(int(r)), "0")) + ">")
			continue
		}
		v.WriteRune(r)
	}
	s := strings.TrimSpace(v.String())
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func anyContains(s string, ks []string) bool {
	for _, k := range ks {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

func hex(n int) string {
	const d = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{d[n%16]}, out...)
		n /= 16
	}
	return string(out)
}

func isInvisible(r rune) bool {
	return r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF ||
		(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || (r >= 0xE0000 && r <= 0xE007F)
}
