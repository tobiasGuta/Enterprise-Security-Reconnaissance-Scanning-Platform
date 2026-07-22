package recon

import (
	"fmt"
	"strings"
)

type Stage struct {
	Key        rune
	Capability string
	Requires   []rune
}

var stages = []Stage{{'s', "discover.subdomains", nil}, {'d', "resolve.dns", []rune{'s'}}, {'n', "scan.ports", []rune{'d'}}, {'h', "probe.http", []rune{'d'}}, {'k', "crawl.web", []rune{'h'}}, {'g', "discover.archive_urls", nil}, {'a', "classify.endpoint", []rune{'k', 'g'}}}

func Validate(pipeline string) error {
	if pipeline == "" {
		return fmt.Errorf("pipeline is empty")
	}
	enabled := map[rune]bool{}
	for _, r := range pipeline {
		if enabled[r] {
			return fmt.Errorf("pipeline stage %q is duplicated", r)
		}
		enabled[r] = true
	}
	for _, s := range stages {
		if !enabled[s.Key] {
			continue
		}
		for _, dependency := range s.Requires {
			if !enabled[dependency] {
				return fmt.Errorf("stage %q (%s) requires stage %q", s.Key, s.Capability, dependency)
			}
		}
	}
	for r := range enabled {
		known := false
		for _, s := range stages {
			if s.Key == r {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("unknown pipeline stage %q; allowed stages are sdnhkga", r)
		}
	}
	return nil
}
func Capabilities(pipeline string) ([]string, error) {
	if err := Validate(pipeline); err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range stages {
		if strings.ContainsRune(pipeline, s.Key) {
			out = append(out, s.Capability)
		}
	}
	return out, nil
}
