//go:build full

package decode

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// ----------------------------------------------------------------- REDIS

var redisCommands = map[string]bool{
	"GET": true, "SET": true, "DEL": true, "EXISTS": true, "EXPIRE": true, "TTL": true,
	"INCR": true, "DECR": true, "MGET": true, "MSET": true, "KEYS": true, "SCAN": true,
	"LPUSH": true, "RPUSH": true, "LPOP": true, "RPOP": true, "LRANGE": true,
	"HSET": true, "HGET": true, "HGETALL": true, "HDEL": true, "SADD": true,
	"SMEMBERS": true, "ZADD": true, "ZRANGE": true, "PUBLISH": true, "SUBSCRIBE": true,
	"PING": true, "INFO": true, "AUTH": true, "SELECT": true, "MULTI": true, "EXEC": true,
	"TYPE": true, "CONFIG": true, "CLIENT": true, "EVAL": true, "SCRIPT": true,
}

func respLine(b []byte, off int) (string, int, bool) {
	if off >= len(b) {
		return "", off, false
	}
	if idx := bytes.Index(b[off:], []byte("\r\n")); idx >= 0 {
		return string(b[off : off+idx]), off + idx + 2, true
	}
	return "", off, false
}

func respValue(b []byte, off, depth int) (string, int, bool) {
	if depth > 6 || off >= len(b) {
		return "", off, false
	}
	switch b[off] {
	case '+', '-', ':':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '$':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return line, next, true
		}
		if next+n > len(b) {
			return "", off, false
		}
		val := string(b[next : next+n])
		next += n
		if next+2 <= len(b) && b[next] == '\r' && b[next+1] == '\n' {
			next += 2
		}
		return val, next, true
	case '*', '~', '>', '%', '|':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 {
			return line, next, true
		}
		count := n
		if b[off] == '%' || b[off] == '|' {
			count = n * 2
		}
		parts := make([]string, 0, count)
		for i := 0; i < count; i++ {
			val, p, ok := respValue(b, next, depth+1)
			if !ok {
				break
			}
			parts = append(parts, val)
			next = p
		}
		if b[off] == '%' || b[off] == '|' {
			pairs := make([]string, 0, n)
			for i := 0; i+1 < len(parts); i += 2 {
				pairs = append(pairs, parts[i]+"="+parts[i+1])
			}
			return strings.Join(pairs, " "), next, true
		}
		return strings.Join(parts, " "), next, true
	case '_':
		_, next, _ := respLine(b, off+1)
		return "null", next, true
	case '#':
		line, next, ok := respLine(b, off+1)
		if ok {
			if line == "t" {
				return "true", next, true
			}
			return "false", next, true
		}
	case ',':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '(':
		line, next, ok := respLine(b, off+1)
		return line, next, ok
	case '=':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 || next+n > len(b) {
			return "", off, false
		}
		if n >= 4 {
			return string(b[next+4 : next+n]), next + n + 2, true
		}
		return string(b[next : next+n]), next + n, true
	case '!':
		line, next, ok := respLine(b, off+1)
		if !ok {
			return "", off, false
		}
		n, err := strconv.Atoi(line)
		if err != nil || n < 0 || next+n > len(b) {
			return "", off, false
		}
		return string(b[next : next+n]), next + n + 2, true
	}
	return "", off, false
}

func (c *ctx) dissectRedis(b []byte, base int) bool {
	if len(b) == 0 {
		return false
	}
	var args []string
	isRESP := strings.ContainsRune("*$+-:_#,(!%~>|=", rune(b[0]))
	val := ""
	if isRESP {
		v, _, ok := respValue(b, 0, 0)
		if !ok {
			return false
		}
		val = v
		args = strings.Split(v, " ")
	} else {
		line, _, ok := respLine(b, 0)
		if !ok {
			return false
		}
		args = strings.Fields(line)
	}
	if len(args) == 0 {
		return false
	}
	cmd := strings.ToUpper(args[0])
	if !redisCommands[cmd] {
		if !isRESP {
			return false
		}
		c.addLayer("redis")
		c.proto = "redis"
		root := c.newNode("Redis RESP3 Reply", base, len(b))
		root.add(c.newField(fmt.Sprintf("Response Type: %c", b[0]), "", base, 1), c.newField("Response: "+shorten(val, 240), "", base, len(b)))
		c.addRoot(root)
		c.appInfo = shorten("Redis reply: "+val, 140)
		return true
	}

	c.addLayer("redis")
	c.proto = "redis"
	root := c.newNode(fmt.Sprintf("Redis (%s)", cmd), base, len(b))
	root.add(c.newField("Command: "+cmd, "", base, len(args[0])))
	for i, arg := range args[1:] {
		root.add(c.newField(fmt.Sprintf("Argument %d: %s", i+1, shorten(arg, 120)), "", base, 0))
	}
	c.addRoot(root)
	c.appInfo = shorten("Redis "+strings.Join(args, " "), 120)
	return true
}

func init() {
	RegisterPlugin(pluginSpec{Name: "redis", Priority: 40, Transport: TransportTCP,
		Match: portMatch(map[uint16]bool{6379: true}), Dissect: func(c *ctx, b []byte, base int) bool { return c.dissectRedis(b, base) }})
}
