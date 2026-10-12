// Command taintscan scans files, directories or stdin for injection and secrets.
//
// Exit codes: 0 clean, 1 findings, 2 usage or scan errors (the scan may be
// incomplete, so errors win over findings).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/AbnormalityAI/taintscan"
)

const maxFileSize = 4 << 20

type report struct {
	File string `json:"file"`
	taintscan.Finding
}

func main() { os.Exit(run()) }

func run() int {
	rulesDir := flag.String("rules", "", "rule directory (default: rules built into the binary)")
	asJSON := flag.Bool("json", false, "JSON output")
	honor := flag.Bool("honor-ignore", false, "skip lines containing taintscan:ignore (only for content you wrote; attackers can add the marker)")
	flag.Parse()
	var rs []taintscan.Rule
	var err error
	if *rulesDir == "" {
		rs, err = taintscan.DefaultRules()
	} else {
		rs, err = taintscan.LoadRules(*rulesDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: loading rules:", err)
		return 2
	}
	opt := taintscan.Options{HonorIgnore: *honor}
	var all []report
	failures := 0
	fail := func(format string, a ...any) {
		failures++
		fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	}
	scan := func(name string, data []byte) {
		for _, f := range taintscan.ScanWith(rs, string(data), opt) {
			all = append(all, report{name, f})
		}
	}
	if flag.NArg() == 0 {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fail("reading stdin: %v", err)
		}
		scan("<stdin>", b)
	}
	for _, root := range flag.Args() {
		if _, err := os.Stat(root); err != nil {
			fail("%v", err)
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				fail("%v", err)
				return nil
			}
			if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				fail("%v", err)
				return nil
			}
			if info.Size() > maxFileSize {
				fail("%s: skipped, larger than %d bytes", p, maxFileSize)
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				fail("%v", err)
				return nil
			}
			scan(p, b)
			return nil
		})
		if err != nil {
			fail("%v", err)
		}
	}
	if *asJSON {
		if all == nil {
			all = []report{}
		}
		json.NewEncoder(os.Stdout).Encode(all)
	} else {
		for _, r := range all {
			fmt.Printf("%s:%d: [%s/%s] %s\n    %s\n", r.File, r.Line, r.Severity, r.Category, r.RuleID, r.Excerpt)
		}
	}
	switch {
	case failures > 0:
		return 2
	case len(all) > 0:
		return 1
	}
	return 0
}
