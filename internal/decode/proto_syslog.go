//go:build full

package decode

import (
	"bytes"
	"fmt"
	"strconv"
)

// ---------------------------------------------------------------- Syslog

var syslogFacilities = []string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}
var syslogSeverities = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

func (c *ctx) dissectSyslog(b []byte, base int) bool {
	if len(b) < 3 || b[0] != '<' {
		return false
	}
	end := bytes.IndexByte(b[:min(6, len(b))], '>')
	if end < 2 {
		return false
	}
	pri, err := strconv.Atoi(string(b[1:end]))
	if err != nil || pri < 0 || pri > 191 {
		return false
	}
	facility := pri / 8
	severity := pri % 8
	facName, sevName := fmt.Sprintf("facility%d", facility), fmt.Sprintf("severity%d", severity)
	if facility < len(syslogFacilities) {
		facName = syslogFacilities[facility]
	}
	if severity < len(syslogSeverities) {
		sevName = syslogSeverities[severity]
	}

	rest := b[end+1:]
	root := c.newNode(fmt.Sprintf("Syslog (%s.%s)", facName, sevName), base, len(b))
	root.add(c.newField(fmt.Sprintf("Priority: %d (%s.%s)", pri, facName, sevName), "", base, end+1))

	info := fmt.Sprintf("syslog %s.%s", facName, sevName)
	if len(rest) > 0 && rest[0] == '1' && len(rest) > 1 && rest[1] == ' ' {
		fields := bytes.SplitN(rest[2:], []byte(" "), 7)
		if len(fields) >= 6 {
			root.add(
				c.newField("Version: 1", "", base+end+1, 1),
				c.newField("Timestamp: "+string(fields[0]), "", base, 0),
				c.newField("Hostname: "+string(fields[1]), "", base, 0),
				c.newField("App Name: "+string(fields[2]), "", base, 0),
				c.newField("Process ID: "+string(fields[3]), "", base, 0),
				c.newField("Message ID: "+string(fields[4]), "", base, 0),
			)
			msg := ""
			if len(fields) >= 7 {
				msg = string(fields[6])
			}
			root.add(c.newField("Message: "+shorten(msg, 200), "", base, 0))
			info = fmt.Sprintf("syslog %s.%s %s %s: %s", facName, sevName, fields[1], fields[2], shorten(msg, 80))
		}
	} else {
		line := shorten(string(rest), 200)
		root.add(c.newField("Message: "+line, "", base+end+1, len(rest)))
		info += " " + shorten(line, 80)
	}
	c.addLayer("syslog")
	c.proto = "syslog"
	c.addRoot(root)
	c.appInfo = info
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "syslog", Priority: 50, Transport: TransportUDP | TransportTCP,
		Match: portMatch(map[uint16]bool{514: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectSyslog(b, base) }})
}
