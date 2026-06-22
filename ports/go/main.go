package main

import (
	"encoding/json"
	"io"
	"os"
)

// Run reads a normalized manifest JSON from r and writes findings JSON to w.
func Run(r io.Reader, w io.Writer) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	findings := AnalyzeManifest(m)
	if findings == nil {
		findings = []Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func main() {
	if err := Run(os.Stdin, os.Stdout); err != nil {
		os.Stderr.WriteString("error: " + err.Error() + "\n")
		os.Exit(1)
	}
}
