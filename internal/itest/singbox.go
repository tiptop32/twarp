//go:build integration

package itest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const singBoxPath = "/opt/homebrew/bin/sing-box"

type socksServer struct {
	listener net.Listener

	mu        sync.Mutex
	counts    map[string]int
	conns     map[net.Conn]struct{}
	waitGroup sync.WaitGroup
	relay     atomic.Bool
}

// EnableRelay makes the stub forward CONNECT requests to their destination
// instead of discarding the payload, so traffic detoured through the gateway
// (for example TCP DNS) actually reaches its target.
func (s *socksServer) EnableRelay() { s.relay.Store(true) }

func startSOCKSServer(t *testing.T) *socksServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for SOCKS5 stub: %v", err)
	}
	server := &socksServer{
		listener: listener,
		counts:   make(map[string]int),
		conns:    make(map[net.Conn]struct{}),
	}
	server.waitGroup.Add(1)
	go server.serve()
	t.Cleanup(func() {
		_ = server.listener.Close()
		server.mu.Lock()
		for conn := range server.conns {
			_ = conn.Close()
		}
		server.mu.Unlock()
		server.waitGroup.Wait()
	})
	return server
}

func (s *socksServer) Port() int {
	return s.listener.Addr().(*net.TCPAddr).Port
}

func (s *socksServer) ConnectCount(destination string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[destination]
}

func (s *socksServer) waitForConnectCount(t *testing.T, destination string, minimum int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.ConnectCount(destination) >= minimum {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(
		"SOCKS5 stub received %d CONNECT requests for %s, want at least %d within %s",
		s.ConnectCount(destination),
		destination,
		minimum,
		timeout,
	)
}

func (s *socksServer) serve() {
	defer s.waitGroup.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.waitGroup.Add(1)
		go s.handle(conn)
	}
}

func (s *socksServer) handle(conn net.Conn) {
	defer s.waitGroup.Done()
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != 5 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	host, err := readSOCKSHost(conn, request[3])
	if err != nil {
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes))))
	s.mu.Lock()
	s.counts[destination]++
	s.mu.Unlock()

	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	if !s.relay.Load() {
		_, _ = io.Copy(io.Discard, conn)
		return
	}
	upstream, err := net.DialTimeout("tcp", destination, 2*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = upstream.Close() }()
	go func() {
		_, _ = io.Copy(upstream, conn)
		_ = upstream.Close()
	}()
	_, _ = io.Copy(conn, upstream)
}

func readSOCKSHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case 1:
		address := make([]byte, net.IPv4len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 4:
		address := make([]byte, net.IPv6len)
		_, err := io.ReadFull(reader, address)
		return net.IP(address).String(), err
	case 3:
		length := make([]byte, 1)
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", err
		}
		address := make([]byte, int(length[0]))
		_, err := io.ReadFull(reader, address)
		return string(address), err
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", addressType)
	}
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type singBoxProcess struct {
	directory   string
	ruleSetPath string
	mixedPort   int
	clashPort   int
	clashSecret string
	command     *exec.Cmd
	log         *lockedBuffer
	done        chan struct{}

	stateMu sync.Mutex
	waitErr error
}

func startSingBox(t *testing.T, socksPort int, initialRuleSet []byte) *singBoxProcess {
	t.Helper()
	if _, err := os.Stat(singBoxPath); err != nil {
		t.Fatalf("sing-box 1.14 binary at %s: %v", singBoxPath, err)
	}
	directory := t.TempDir()
	ruleSetPath := filepath.Join(directory, "gateway-ip.json")
	if err := os.WriteFile(ruleSetPath, initialRuleSet, 0o600); err != nil {
		t.Fatalf("write initial rule-set: %v", err)
	}

	template, err := os.ReadFile(filepath.Join("testdata", "hotreload.json"))
	if err != nil {
		t.Fatalf("read sing-box config template: %v", err)
	}
	mixedPort := freePort(t)
	clashPort := freePort(t)
	const clashSecret = "twarp-itest"
	config := strings.NewReplacer(
		"{{MIXED_PORT}}", strconv.Itoa(mixedPort),
		"{{SOCKS_PORT}}", strconv.Itoa(socksPort),
		"{{CLASH_PORT}}", strconv.Itoa(clashPort),
		"{{CLASH_SECRET}}", clashSecret,
		"{{RULE_SET_PATH}}", jsonStringContents(ruleSetPath),
	).Replace(string(template))
	if !json.Valid([]byte(config)) {
		t.Fatalf("rendered sing-box config is not valid JSON:\n%s", config)
	}
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("write sing-box config: %v", err)
	}

	box := startSingBoxWithConfig(t, configPath, mixedPort, clashPort, clashSecret)
	box.ruleSetPath = ruleSetPath
	return box
}

func startSingBoxWithConfig(
	t *testing.T,
	configPath string,
	mixedPort int,
	clashPort int,
	clashSecret string,
) *singBoxProcess {
	t.Helper()
	if _, err := os.Stat(singBoxPath); err != nil {
		t.Fatalf("sing-box 1.14 binary at %s: %v", singBoxPath, err)
	}
	directory := filepath.Dir(configPath)
	box := &singBoxProcess{
		directory:   directory,
		ruleSetPath: filepath.Join(directory, "rules", "gateway-ip.json"),
		mixedPort:   mixedPort,
		clashPort:   clashPort,
		clashSecret: clashSecret,
		log:         &lockedBuffer{},
		done:        make(chan struct{}),
	}
	box.command = exec.Command(singBoxPath, "run", "-c", configPath)
	box.command.Dir = directory
	box.command.Stdout = box.log
	box.command.Stderr = box.log
	if err := box.command.Start(); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	go func() {
		err := box.command.Wait()
		box.stateMu.Lock()
		box.waitErr = err
		box.stateMu.Unlock()
		close(box.done)
	}()
	t.Cleanup(box.stop)
	box.waitUntilReady(t)
	return box
}

func (b *singBoxProcess) stop() {
	select {
	case <-b.done:
		return
	default:
	}
	_ = b.command.Process.Signal(os.Interrupt)
	select {
	case <-b.done:
	case <-time.After(2 * time.Second):
		_ = b.command.Process.Kill()
		<-b.done
	}
}

func (b *singBoxProcess) waitUntilReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-b.done:
			b.stateMu.Lock()
			err := b.waitErr
			b.stateMu.Unlock()
			t.Fatalf("sing-box exited before readiness: %v\n%s", err, b.Log())
		default:
		}
		inboundReady := b.mixedPort == 0
		if !inboundReady {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(b.mixedPort)), 100*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				inboundReady = true
			}
		}
		if inboundReady {
			if _, err := b.connections(); err == nil {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sing-box was not ready within 5s:\n%s", b.Log())
}

func (b *singBoxProcess) openCONNECT(t *testing.T, destination string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(b.mixedPort)), time.Second)
	if err != nil {
		t.Fatalf("connect to mixed inbound: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil || response[0] != 5 || response[1] != 0 {
		_ = conn.Close()
		t.Fatalf("read SOCKS5 greeting response: response=%v err=%v", response, err)
	}

	host, portText, err := net.SplitHostPort(destination)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("parse destination %q: %v", destination, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		_ = conn.Close()
		t.Fatalf("parse destination port %q: %v", portText, err)
	}
	request := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			request = append(request, 1)
			request = append(request, ipv4...)
		} else {
			request = append(request, 4)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			_ = conn.Close()
			t.Fatalf("SOCKS5 destination host is too long: %q", host)
		}
		request = append(request, 3, byte(len(host)))
		request = append(request, host...)
	}
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn
}

type clashConnections struct {
	Connections []struct {
		Chains   []string `json:"chains"`
		Metadata struct {
			DestinationIP   string `json:"destinationIP"`
			DestinationPort string `json:"destinationPort"`
			Host            string `json:"host"`
		} `json:"metadata"`
	} `json:"connections"`
}

func (b *singBoxProcess) connections() (clashConnections, error) {
	request, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/connections", b.clashPort), nil)
	if err != nil {
		return clashConnections{}, err
	}
	request.Header.Set("Authorization", "Bearer "+b.clashSecret)
	client := &http.Client{Timeout: 200 * time.Millisecond}
	response, err := client.Do(request)
	if err != nil {
		return clashConnections{}, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return clashConnections{}, fmt.Errorf("clash API returned %s", response.Status)
	}
	var result clashConnections
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return clashConnections{}, err
	}
	return result, nil
}

func (b *singBoxProcess) outboundWithin(destination, tag string, timeout time.Duration) bool {
	host, port, _ := net.SplitHostPort(destination)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connections, err := b.connections()
		if err == nil {
			for _, connection := range connections.Connections {
				if (connection.Metadata.DestinationIP == host || connection.Metadata.Host == host) &&
					connection.Metadata.DestinationPort == port &&
					contains(connection.Chains, tag) {
					return true
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func (b *singBoxProcess) waitForOutbound(t *testing.T, destination, tag string, timeout time.Duration) {
	t.Helper()
	if !b.outboundWithin(destination, tag, timeout) {
		t.Fatalf("did not observe outbound %q for %s within %s; sing-box log:\n%s", tag, destination, timeout, b.Log())
	}
}

func (b *singBoxProcess) waitForNoOutbound(t *testing.T, destination string, timeout time.Duration) {
	t.Helper()
	host, port, _ := net.SplitHostPort(destination)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		connections, err := b.connections()
		if err == nil {
			found := false
			for _, connection := range connections.Connections {
				if (connection.Metadata.DestinationIP == host || connection.Metadata.Host == host) &&
					connection.Metadata.DestinationPort == port {
					found = true
					break
				}
			}
			if !found {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connection to %s remained in Clash API after close", destination)
}

func (b *singBoxProcess) replaceRuleSet(t *testing.T, contents []byte) {
	t.Helper()
	if !json.Valid(contents) {
		t.Fatalf("replacement rule-set is not valid JSON: %s", contents)
	}
	b.replaceRuleSetRaw(t, contents)
}

func (b *singBoxProcess) replaceRuleSetRaw(t *testing.T, contents []byte) {
	t.Helper()
	temporaryPath := filepath.Join(b.directory, ".gateway-ip.json.tmp")
	if err := os.WriteFile(temporaryPath, contents, 0o600); err != nil {
		t.Fatalf("write temporary rule-set: %v", err)
	}
	if err := os.Rename(temporaryPath, b.ruleSetPath); err != nil {
		t.Fatalf("rename replacement rule-set: %v", err)
	}
}

func (b *singBoxProcess) waitForLogAfter(t *testing.T, offset int, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log := b.Log()
		if offset < len(log) {
			newLog := log[offset:]
			if strings.Contains(strings.ToLower(newLog), "error") {
				return newLog
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("sing-box did not log a rule-set reload error within %s; log:\n%s", timeout, b.Log())
	return ""
}

func (b *singBoxProcess) requireRunning(t *testing.T) {
	t.Helper()
	select {
	case <-b.done:
		b.stateMu.Lock()
		err := b.waitErr
		b.stateMu.Unlock()
		t.Fatalf("sing-box exited unexpectedly: %v\n%s", err, b.Log())
	default:
	}
}

func (b *singBoxProcess) Log() string {
	return b.log.String()
}

func sourceRuleSet(prefixes ...string) []byte {
	rules := make([]any, 0, 1)
	if len(prefixes) > 0 {
		rules = append(rules, map[string]any{"ip_cidr": prefixes})
	}
	contents, err := json.Marshal(map[string]any{
		"version": 2,
		"rules":   rules,
	})
	if err != nil {
		panic(err)
	}
	return contents
}

func checkSingBox(t *testing.T, config []byte) (string, error) {
	t.Helper()
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		t.Fatalf("write config for sing-box check: %v", err)
	}
	command := exec.Command(singBoxPath, "check", "-c", configPath)
	command.Dir = directory
	output, err := command.CombinedOutput()
	return string(output), err
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free TCP port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatalf("release free TCP port: %v", err)
	}
	return port
}

func jsonStringContents(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(quoted[1 : len(quoted)-1])
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
