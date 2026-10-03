package state

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"
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
	file, err := os.OpenFile(s.opts.AuditFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open audit %q: %w", s.opts.AuditFile, err)
	}
	record := auditRecord{
		TS: s.now(), Actor: actor, Op: operation, Input: input, Result: result, CIDR: prefix,
	}
	if err := json.NewEncoder(file).Encode(record); err != nil {
		_ = file.Close()
		return fmt.Errorf("append audit %q: %w", s.opts.AuditFile, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close audit %q: %w", s.opts.AuditFile, err)
	}
	return nil
}
