//go:build integration

package itest

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/tiptop32/twarp/internal/singbox"
	"github.com/tiptop32/twarp/internal/sysexec"
)

func TestSingBoxVersionAndClashAPI(t *testing.T) {
	version, err := singbox.Version(context.Background(), sysexec.ExecRunner{}, singBoxPath)
	if err != nil {
		t.Fatalf("Version() error = %v", err)
	}
	if err := singbox.RequireMinVersion(version, singbox.MinMajor, singbox.MinMinor); err != nil {
		t.Fatalf("RequireMinVersion(%q) error = %v", version, err)
	}

	proxy := startSOCKSServer(t)
	box := startSingBox(t, proxy.Port(), sourceRuleSet())
	client := singbox.Clash{
		Addr:   net.JoinHostPort("127.0.0.1", strconv.Itoa(box.clashPort)),
		Secret: box.clashSecret,
	}
	clashVersion, err := client.Version(context.Background())
	if err != nil {
		t.Fatalf("Clash.Version() error = %v", err)
	}
	if clashVersion == "" {
		t.Fatal("Clash.Version() returned an empty version")
	}

	connection := box.openCONNECT(t, testDestination)
	t.Cleanup(func() { _ = connection.Close() })
	box.waitForOutbound(t, testDestination, "direct", time.Second)

	connections, err := client.Connections(context.Background())
	if err != nil {
		t.Fatalf("Clash.Connections() error = %v", err)
	}
	host, port, _ := net.SplitHostPort(testDestination)
	for _, active := range connections {
		if active.DestinationIP == host && active.DestinationPort == port {
			if got := active.Outbound(); got != "direct" {
				t.Fatalf("Outbound() = %q for chains %v, want %q", got, active.Chains, "direct")
			}
			return
		}
	}
	t.Fatalf("Clash.Connections() did not include %s: %#v", testDestination, connections)
}
