package taintscan

import (
	"os"
	"strings"
	"testing"
)

func rules(t *testing.T) []Rule {
	rs, err := LoadRules("rules")
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestCorpusPositivesFireExactly(t *testing.T) {
	rs := rules(t)
	samples, err := LoadCorpus("corpus")
	if err != nil || len(samples) == 0 {
		t.Fatalf("corpus: %v (%d)", err, len(samples))
	}
	for _, s := range samples {
		got := map[string]bool{}
		for _, f := range Scan(rs, s.Text) {
			got[f.RuleID] = true
		}
		want := map[string]bool{}
		for _, id := range s.Expect {
			want[id] = true
		}
		for id := range want {
			if !got[id] {
				t.Errorf("%s: missing %s", s.Name, id)
			}
		}
		for id := range got {
			if !want[id] {
				t.Errorf("%s: unexpected %s (false positive)", s.Name, id)
			}
		}
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	rs := rules(t)
	tok := "gh" + "p_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
	fs := Scan(rs, "token: "+tok)
	if len(fs) == 0 {
		t.Fatal("no finding")
	}
	for _, f := range fs {
		if strings.Contains(f.Excerpt, tok) || strings.Contains(f.Excerpt, tok[:20]) {
			t.Fatalf("excerpt leaks secret: %q", f.Excerpt)
		}
	}
}

func TestInvisibleCharsMadeVisible(t *testing.T) {
	fs := Scan(rules(t), "a\u200bb")
	if len(fs) != 1 || !strings.Contains(fs[0].Excerpt, "<U+200B>") {
		t.Fatalf("%+v", fs)
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaaaaaa") != 0 || Entropy("abcdefgh") < 2.9 {
		t.Fatal("entropy wrong")
	}
}

func TestEveryRuleHasPositiveCoverage(t *testing.T) {
	covered := map[string]bool{}
	samples, _ := LoadCorpus("corpus")
	for _, s := range samples {
		for _, id := range s.Expect {
			covered[id] = true
		}
	}
	for _, r := range rules(t) {
		if !covered[r.ID] {
			t.Errorf("rule %s has no positive corpus sample", r.ID)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
