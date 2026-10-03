//go:build integration

// Package itest exercises twarp's sing-box assumptions against the real binary.
package itest

import (
	"net"
	"strings"
	"testing"
	"time"
)

const testDestination = "100.66.90.10:80"

func TestLocalRuleSetEmptyRulesAndHotReloadByRename(t *testing.T) {
	proxy := startSOCKSServer(t)
	box := startSingBox(t, proxy.Port(), sourceRuleSet())

	directConn := box.openCONNECT(t, testDestination)
	box.waitForOutbound(t, testDestination, "direct", time.Second)
	_ = directConn.Close()
	if got := proxy.ConnectCount(testDestination); got != 0 {
		t.Fatalf("empty rule-set sent %d CONNECT requests to corp proxy, want 0", got)
	}

	started := time.Now()
	connectsBeforeReload := proxy.ConnectCount(testDestination)
	box.replaceRuleSet(t, sourceRuleSet("100.66.90.10/32"))
	deadline := started.Add(3 * time.Second)
	var corpConn net.Conn
	for time.Now().Before(deadline) {
		candidate := box.openCONNECT(t, testDestination)
		if box.outboundWithin(testDestination, "corp", 150*time.Millisecond) {
			proxy.waitForConnectCount(t, testDestination, connectsBeforeReload+1, time.Until(deadline))
			corpConn = candidate
			break
		}
		_ = candidate.Close()
	}
	if corpConn == nil {
		t.Fatalf("rule-set was not reloaded within 3s; sing-box log:\n%s", box.Log())
	}
	t.Cleanup(func() { _ = corpConn.Close() })
	elapsed := time.Since(started)
	t.Logf("sing-box applied the renamed rule-set in %s", elapsed)
	if elapsed > 3*time.Second {
		t.Fatalf("rule-set reload took %s, want at most 3s", elapsed)
	}
}

func TestLocalRuleSetVersion2KeepsOldRulesAfterInvalidReload(t *testing.T) {
	proxy := startSOCKSServer(t)
	box := startSingBox(t, proxy.Port(), sourceRuleSet("100.66.90.10/32"))

	first := box.openCONNECT(t, testDestination)
	box.waitForOutbound(t, testDestination, "corp", time.Second)
	_ = first.Close()
	box.waitForNoOutbound(t, testDestination, time.Second)
	before := proxy.ConnectCount(testDestination)
	logOffset := len(box.Log())

	box.replaceRuleSetRaw(t, []byte(`{"version": 2, "rules": [`))
	newLog := box.waitForLogAfter(t, logOffset, 3*time.Second)
	if !strings.Contains(strings.ToLower(newLog), "error") {
		t.Fatalf("invalid reload did not log an error; new log:\n%s", newLog)
	}
	box.requireRunning(t)

	second := box.openCONNECT(t, testDestination)
	t.Cleanup(func() { _ = second.Close() })
	box.waitForOutbound(t, testDestination, "corp", time.Second)
	proxy.waitForConnectCount(t, testDestination, before+1, time.Second)
}

func TestCheckRequiresDefaultDomainResolver(t *testing.T) {
	config := []byte(`{
  "log": {"disabled": true},
  "dns": {
    "servers": [
      {"type": "udp", "tag": "dns-a", "server": "dns.google"},
      {"type": "udp", "tag": "dns-b", "server": "one.one.one.one"}
    ],
    "final": "dns-a"
  },
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}`)

	output, err := checkSingBox(t, config)
	if err == nil {
		t.Fatalf("sing-box check accepted domain-addressed DNS servers without default_domain_resolver")
	}
	if !strings.Contains(output, "missing domain resolver for domain server address") {
		t.Fatalf("sing-box check failed for the wrong reason: %v\n%s", err, output)
	}
}
