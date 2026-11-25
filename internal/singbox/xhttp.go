package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// Validate checks XHTTP settings that must work through the fixed TCP bridge.
// Xray validates the remaining extra fields when installing the client.
func (x *XHTTP) Validate() error {
	switch x.Mode {
	case "", "auto", "packet-up", "stream-up", "stream-one":
	default:
		return errors.New("invalid xhttp mode")
	}
	if len(x.Extra) == 0 {
		return nil
	}
	var extra map[string]json.RawMessage
	if err := json.Unmarshal(x.Extra, &extra); err != nil || extra == nil {
		return errors.New("xhttp extra must be a JSON object")
	}
	for key, value := range extra {
		// A separate download stream has its own destination and transport;
		// the single fixed-destination TCP bridge cannot carry that route.
		if strings.EqualFold(key, "downloadSettings") && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("xhttp downloadSettings is not supported by the local bridge")
		}
	}
	return nil
}
