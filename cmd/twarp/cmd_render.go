package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/app"
	"github.com/tiptop32/twarp/internal/render"
)

func runRender(args []string, stdout, stderr io.Writer, deps cliDeps) int {
	fs := flag.NewFlagSet("twarp render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "write config.json and rules/gateway-ip.json to DIR")
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

	_, prefixes, data, err := deps.app(app.ActorCLI).RenderInputs()
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

	rulesDir := filepath.Join(*out, "rules")
	data, err = setGatewayRuleSetPath(data, render.RuleSetPath(rulesDir))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: prepare output: %v\n", err)
		return 1
	}
	configPath := filepath.Join(*out, "config.json")
	if err := render.WriteConfig(configPath, data); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: %v\n", err)
		return 1
	}
	if err := render.WriteRuleSet(rulesDir, prefixes); err != nil {
		_, _ = fmt.Fprintf(stderr, "twarp render: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "rendered %s and %s\n", configPath, render.RuleSetPath(rulesDir))
	return 0
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

func setGatewayRuleSetPath(data []byte, path string) ([]byte, error) {
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
		if ok && ruleSet["tag"] == "gateway-ip" {
			ruleSet["path"] = path
			return marshalDocument(document)
		}
	}
	return nil, errors.New("rendered config has no gateway-ip rule-set")
}

func marshalDocument(document any) ([]byte, error) {
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
