package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/config"
	"github.com/tiptop32/twarp/internal/render"
	"github.com/tiptop32/twarp/internal/state"
)

func runRender(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	fs := flag.NewFlagSet("twarp render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write config.json and rules/corp-ip.json to DIR")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "twarp render: unexpected arguments: %v\n", fs.Args())
		return 2
	}

	_, prefixes, data, err := renderInputs(deps.Sys)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: %v\n", err)
		return 1
	}
	if *out == "" {
		masked, err := maskRenderedSecrets(data)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "twarp render: mask secrets: %v\n", err)
			return 1
		}
		_, _ = stdout.Write(masked)
		return 0
	}

	data, err = setCorpRuleSetPath(data, filepath.Join(*out, "rules", "corp-ip.json"))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: prepare output: %v\n", err)
		return 1
	}
	configPath := filepath.Join(*out, "config.json")
	if err := render.WriteConfig(configPath, data); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: %v\n", err)
		return 1
	}
	if err := render.WriteRuleSet(filepath.Join(*out, "rules"), prefixes); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "rendered %s and %s\n", configPath, filepath.Join(*out, "rules", "corp-ip.json"))
	return 0
}

func renderInputs(system config.Sys) (config.Paths, []netip.Prefix, []byte, error) {
	paths, err := config.Resolve(system)
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	cfg, err := config.Load(paths.ConfigFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	secrets, err := config.LoadSecrets(paths.SecretsFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	prefixes, err := state.ReadPrefixes(paths.CorpIPsFile(), paths.LockFile())
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	data, err := render.Render(cfg, secrets, prefixes, render.Options{Paths: paths, Inbound: render.InboundTUN})
	if err != nil {
		return config.Paths{}, nil, nil, err
	}
	return paths, prefixes, data, nil
}

func maskRenderedSecrets(data []byte) ([]byte, error) {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	maskJSONKeys(document, map[string]struct{}{
		"uuid": {}, "public_key": {}, "short_id": {}, "secret": {},
	})
	return marshalDocument(document)
}

func maskJSONKeys(value any, keys map[string]struct{}) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if _, ok := keys[key]; ok {
				typed[key] = "***"
				continue
			}
			maskJSONKeys(child, keys)
		}
	case []any:
		for _, child := range typed {
			maskJSONKeys(child, keys)
		}
	}
}

func setCorpRuleSetPath(data []byte, path string) ([]byte, error) {
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, err
	}
	route, ok := document["route"].(map[string]any)
	if !ok {
		return nil, errors.New("rendered config has no route object")
	}
	ruleSets, ok := route["rule_set"].([]any)
	if !ok {
		return nil, errors.New("rendered config has no route.rule_set array")
	}
	for _, value := range ruleSets {
		ruleSet, ok := value.(map[string]any)
		if ok && ruleSet["tag"] == "corp-ip" {
			ruleSet["path"] = path
			return marshalDocument(document)
		}
	}
	return nil, errors.New("rendered config has no corp-ip rule-set")
}

func marshalDocument(document any) ([]byte, error) {
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
