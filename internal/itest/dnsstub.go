//go:build integration

package itest

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsStub struct {
	network string
	packet  net.PacketConn
	stream  net.Listener

	mu      sync.Mutex
	queries map[string]int
	done    chan struct{}
}

type dnsEndpoint struct {
	network string
	port    int
	// keepDetour leaves the rendered detour in place so the query takes the
	// production path (for the gateway server: TCP through the SOCKS gateway).
	keepDetour bool
}

func startDNSStub(t *testing.T, network string) *dnsStub {
	t.Helper()
	stub := &dnsStub{network: network, queries: make(map[string]int), done: make(chan struct{})}
	var err error
	switch network {
	case "udp":
		stub.packet, err = net.ListenPacket("udp", "127.0.0.1:0")
	case "tcp":
		stub.stream, err = net.Listen("tcp", "127.0.0.1:0")
	default:
		t.Fatalf("unsupported DNS stub network %q", network)
	}
	if err != nil {
		t.Fatalf("listen for %s DNS stub: %v", network, err)
	}
	go stub.serve()
	t.Cleanup(func() {
		if stub.packet != nil {
			_ = stub.packet.Close()
		} else {
			_ = stub.stream.Close()
		}
		<-stub.done
	})
	return stub
}

func (s *dnsStub) Port() int {
	if s.packet != nil {
		return s.packet.LocalAddr().(*net.UDPAddr).Port
	}
	return s.stream.Addr().(*net.TCPAddr).Port
}

func (s *dnsStub) QueryCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries[normalizeDNSName(name)]
}

func (s *dnsStub) serve() {
	defer close(s.done)
	if s.network == "udp" {
		s.serveUDP()
		return
	}
	for {
		connection, err := s.stream.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(connection)
	}
}

func (s *dnsStub) serveUDP() {
	buffer := make([]byte, 64*1024)
	for {
		length, address, err := s.packet.ReadFrom(buffer)
		if err != nil {
			return
		}
		response, err := s.response(buffer[:length])
		if err == nil {
			_, _ = s.packet.WriteTo(response, address)
		}
	}
}

func (s *dnsStub) handleTCP(connection net.Conn) {
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, lengthBytes); err != nil {
		return
	}
	query := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
	if _, err := io.ReadFull(connection, query); err != nil {
		return
	}
	response, err := s.response(query)
	if err != nil {
		return
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(response)))
	framed = append(framed, response...)
	_, _ = connection.Write(framed)
}

func (s *dnsStub) response(query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil, err
	}
	question, err := parser.Question()
	if err != nil {
		return nil, err
	}
	name := normalizeDNSName(question.Name.String())
	s.mu.Lock()
	s.queries[name]++
	s.mu.Unlock()

	responseHeader := dnsmessage.Header{
		ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true,
	}
	builder := dnsmessage.NewBuilder(nil, responseHeader)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if question.Type == dnsmessage.TypeA {
		answer := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}
		if err := builder.AResource(answer, dnsmessage.AResource{A: [4]byte{198, 51, 100, 10}}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

func patchDNSServers(t *testing.T, configPath string, endpoints map[string]dnsEndpoint) {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode rendered config: %v", err)
	}
	dnsConfig, ok := document["dns"].(map[string]any)
	if !ok {
		t.Fatal("rendered config has no dns object")
	}
	servers, ok := dnsConfig["servers"].([]any)
	if !ok {
		t.Fatal("rendered config has no dns.servers array")
	}
	seen := make(map[string]bool, len(endpoints))
	for _, rawServer := range servers {
		server, ok := rawServer.(map[string]any)
		if !ok {
			t.Fatalf("invalid DNS server entry: %#v", rawServer)
		}
		tag, _ := server["tag"].(string)
		endpoint, exists := endpoints[tag]
		if !exists {
			continue
		}
		server["type"] = endpoint.network
		server["server"] = "127.0.0.1"
		server["server_port"] = endpoint.port
		delete(server, "path")
		if !endpoint.keepDetour {
			delete(server, "detour")
		}
		seen[tag] = true
	}
	for tag := range endpoints {
		if !seen[tag] {
			t.Fatalf("rendered config has no DNS server tagged %q", tag)
		}
	}
	patched, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode patched config: %v", err)
	}
	patched = append(patched, '\n')
	if err := os.WriteFile(configPath, patched, 0o600); err != nil {
		t.Fatalf("write patched config: %v", err)
	}
}

func patchDirectDNSInbound(t *testing.T, configPath string, port int) {
	t.Helper()
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read rendered config: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode rendered config: %v", err)
	}
	document["inbounds"] = []any{map[string]any{
		"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": port,
		"network": "udp", "override_address": "192.0.2.53", "override_port": 53,
	}}
	patched, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("encode DNS inbound config: %v", err)
	}
	patched = append(patched, '\n')
	if err := os.WriteFile(configPath, patched, 0o600); err != nil {
		t.Fatalf("write DNS inbound config: %v", err)
	}
}

func queryDNS(t *testing.T, port int, domain string) {
	t.Helper()
	name, err := dnsmessage.NewName(domain + ".")
	if err != nil {
		t.Fatalf("construct DNS name %q: %v", domain, err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1600, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatalf("start DNS question: %v", err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatalf("add DNS question: %v", err)
	}
	query, err := builder.Finish()
	if err != nil {
		t.Fatalf("finish DNS query: %v", err)
	}
	connection, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
	if err != nil {
		t.Fatalf("dial DNS inbound: %v", err)
	}
	defer func() { _ = connection.Close() }()
	_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := connection.Write(query); err != nil {
		t.Fatalf("write DNS query for %s: %v", domain, err)
	}
	response := make([]byte, 4096)
	length, err := connection.Read(response)
	if err != nil {
		t.Fatalf("read DNS response for %s: %v", domain, err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(response[:length])
	if err != nil || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("parse DNS response for %s: header=%#v err=%v", domain, header, err)
	}
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}
