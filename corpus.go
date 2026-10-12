package taintscan

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Sample is one labelled corpus file.
type Sample struct {
	Name   string
	Text   string
	Expect []string // rule IDs that must fire; empty for negative samples
}

// LoadCorpus reads corpus files. The first line may be "# expect: id1,id2".
// The marker <CUT> is deleted from the text, which lets the repo store
// token-shaped test data without containing a contiguous secret-looking
// string (keeps push protection and other scanners quiet).
func LoadCorpus(dir string) ([]Sample, error) {
	var out []Sample
	paths, err := filepath.Glob(filepath.Join(dir, "*", "*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var s Sample
		s.Name = filepath.Base(filepath.Dir(p)) + "/" + filepath.Base(p)
		var body []string
		for i := 0; sc.Scan(); i++ {
			line := sc.Text()
			if i == 0 && strings.HasPrefix(line, "# expect:") {
				for _, id := range strings.Split(strings.TrimPrefix(line, "# expect:"), ",") {
					if id = strings.TrimSpace(id); id != "" {
						s.Expect = append(s.Expect, id)
					}
				}
				continue
			}
			body = append(body, line)
		}
		scanErr := sc.Err()
		f.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("%s: %w", p, scanErr)
		}
		s.Text = strings.ReplaceAll(strings.Join(body, "\n"), "<CUT>", "")
		out = append(out, s)
	}
	return out, nil
}
