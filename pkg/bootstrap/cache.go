package bootstrap

import (
	"log/slog"
	"sync"
	"time"
)

type entry struct {
	ip string
	ts time.Time
}

var (
	records    = make(map[string]entry)
	recordsMux sync.RWMutex
	ttl        = 10 * time.Minute
)

func Cache(domain string) (string, error) {
	recordsMux.RLock()
	e, ok := records[domain]
	recordsMux.RUnlock()

	// 命中缓存
	if ok && time.Since(e.ts) < ttl {
		slog.Info("cache hit", "domain", domain, "ip", e.ip)
		return e.ip, nil
	}

	ip, err := Resolve(domain)
	if err != nil {
		return "", err
	}

	// 更新缓存
	recordsMux.Lock()
	records[domain] = entry{ip: ip, ts: time.Now()}
	recordsMux.Unlock()

	slog.Info("cache update", "domain", domain, "ip", ip)

	return ip, nil
}
