package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

const (
	defaultClashTimeout = 2 * time.Second
	runningTimeout      = time.Second
)

// ErrUnauthorized reports rejected Clash API credentials.
var ErrUnauthorized = errors.New("clash API unauthorized")

// Clash is a client for sing-box's Clash-compatible API.
type Clash struct {
	Addr   string
	Secret string
	Client *http.Client
}

// Connection is the routing information exposed by the Clash API.
type Connection struct {
	Chains          []string
	DestinationIP   string
	DestinationPort string
	Host            string
}

// Outbound returns the final outbound selected for the connection. sing-box
// orders chains from outbound to inbound, so the first element is the final
// outbound rather than the last hop listed by some Clash implementations.
func (c Connection) Outbound() string {
	if len(c.Chains) == 0 {
		return ""
	}
	return c.Chains[0]
}

// Version returns the version string reported by the Clash API unchanged.
func (c Clash) Version(ctx context.Context) (string, error) {
	var response struct {
		Version string `json:"version"`
	}
	if err := c.get(ctx, "/version", &response); err != nil {
		return "", err
	}
	return response.Version, nil
}

// Connections returns the active connections known to sing-box.
func (c Clash) Connections(ctx context.Context) ([]Connection, error) {
	var response struct {
		Connections []struct {
			Chains   []string `json:"chains"`
			Metadata struct {
				DestinationIP   string `json:"destinationIP"`
				DestinationPort string `json:"destinationPort"`
				Host            string `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := c.get(ctx, "/connections", &response); err != nil {
		return nil, err
	}

	connections := make([]Connection, len(response.Connections))
	for index, connection := range response.Connections {
		connections[index] = Connection{
			Chains:          connection.Chains,
			DestinationIP:   connection.Metadata.DestinationIP,
			DestinationPort: connection.Metadata.DestinationPort,
			Host:            connection.Metadata.Host,
		}
	}
	return connections, nil
}

// Running reports whether the Clash API responds to a version request. A 401
// still proves sing-box is up; only the secret is wrong.
func (c Clash) Running(ctx context.Context) bool {
	_, err := c.Version(ctx)
	return err == nil || errors.Is(err, ErrUnauthorized)
}

// RunningFunc adapts Running to state.Options.Running and bounds each probe to
// one second independently of the caller.
func (c Clash) RunningFunc() func() bool {
	return func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), runningTimeout)
		defer cancel()
		return c.Running(ctx)
	}
}

func (c Clash) get(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.Addr+path, nil)
	if err != nil {
		return fmt.Errorf("clash API GET %s: %w", path, err)
	}
	if c.Secret != "" {
		request.Header.Set("Authorization", "Bearer "+c.Secret)
	}

	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: defaultClashTimeout}
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("clash API GET %s: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("clash API GET %s: %w", path, ErrUnauthorized)
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("clash API GET %s: unexpected status %s", path, response.Status)
	}
	if err := json.NewDecoder(response.Body).Decode(destination); err != nil {
		return fmt.Errorf("clash API decode GET %s: %w", path, err)
	}
	return nil
}
