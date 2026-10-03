// Package launchd installs and removes twarp launchd services.
package launchd

import (
	"bytes"
	"encoding/xml"
	"errors"
	"path/filepath"

	"github.com/tiptop32/twarp/internal/config"
)

const (
	// SingBoxPlistPath is the system launch daemon definition for sing-box.
	SingBoxPlistPath = "/Library/LaunchDaemons/dev.twarp.singbox.plist"
	// GeoPlistPath is the system launch daemon definition for daily geo updates.
	GeoPlistPath = "/Library/LaunchDaemons/dev.twarp.geo.plist"
	// NewsyslogPath is the sing-box log rotation definition.
	NewsyslogPath = "/etc/newsyslog.d/twarp.conf"
	logDir        = "/usr/local/var/log/twarp"
	workingDir    = "/usr/local/var/lib/twarp"
)

const plistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
`

// SingBoxPlist renders the system launch daemon for sing-box.
func SingBoxPlist(paths config.Paths) ([]byte, error) {
	if !filepath.IsAbs(paths.SingBox) {
		return nil, errors.New("sing-box path must be absolute")
	}
	if !filepath.IsAbs(paths.OutConfig()) {
		return nil, errors.New("sing-box config path must be absolute")
	}

	var output bytes.Buffer
	output.WriteString(plistHeader)
	writeKeyString(&output, "Label", "dev.twarp.singbox", 2)
	output.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, argument := range []string{paths.SingBox, "run", "-c", paths.OutConfig()} {
		writeString(&output, argument, 4)
	}
	output.WriteString("  </array>\n")
	output.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	output.WriteString("  <key>KeepAlive</key>\n  <true/>\n")
	writeKeyString(&output, "WorkingDirectory", workingDir, 2)
	writeKeyString(&output, "StandardOutPath", filepath.Join(logDir, "sing-box.log"), 2)
	writeKeyString(&output, "StandardErrorPath", filepath.Join(logDir, "sing-box.log"), 2)
	output.WriteString("</dict>\n</plist>\n")
	return output.Bytes(), nil
}

// GeoPlist renders the daily geo updater. It is intentionally a root
// LaunchDaemon, not a GUI agent, because geo update writes root-owned files.
func GeoPlist(executable string) ([]byte, error) {
	if !filepath.IsAbs(executable) {
		return nil, errors.New("twarp executable path must be absolute")
	}

	var output bytes.Buffer
	output.WriteString(plistHeader)
	writeKeyString(&output, "Label", "dev.twarp.geo", 2)
	output.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, argument := range []string{executable, "geo", "update"} {
		writeString(&output, argument, 4)
	}
	output.WriteString("  </array>\n")
	output.WriteString("  <key>StartInterval</key>\n  <integer>86400</integer>\n")
	output.WriteString("  <key>RunAtLoad</key>\n  <false/>\n")
	output.WriteString("</dict>\n</plist>\n")
	return output.Bytes(), nil
}

// NewsyslogConfig returns the sing-box log rotation rule.
func NewsyslogConfig() []byte {
	return []byte("/usr/local/var/log/twarp/sing-box.log 644 5 1024 * NJ\n")
}

func writeKeyString(output *bytes.Buffer, key, value string, indent int) {
	output.WriteString(string(bytes.Repeat([]byte(" "), indent)))
	output.WriteString("<key>")
	_ = xml.EscapeText(output, []byte(key))
	output.WriteString("</key>\n")
	writeString(output, value, indent)
}

func writeString(output *bytes.Buffer, value string, indent int) {
	output.Write(bytes.Repeat([]byte(" "), indent))
	output.WriteString("<string>")
	_ = xml.EscapeText(output, []byte(value))
	output.WriteString("</string>\n")
}
