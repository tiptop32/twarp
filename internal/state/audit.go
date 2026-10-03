package state

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/tiptop32/twarp/internal/fsutil"
)

type auditRecord struct {
	TS     time.Time    `json:"ts"`
	Actor  string       `json:"actor"`
	Op     string       `json:"op"`
	Input  string       `json:"input"`
	Result string       `json:"result"`
	CIDR   netip.Prefix `json:"cidr"`
}

func (s *Store) appendAudit(actor, operation, input, result string, prefix netip.Prefix) error {
	record := auditRecord{
		TS: s.now(), Actor: actor, Op: operation, Input: input, Result: result, CIDR: prefix,
	}
	if err := fsutil.AppendJSONLine(s.opts.AuditFile, record); err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}
