package godns

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/miekg/dns"
)

type CacheValue struct {
	M *dns.Msg
	T int64
}

type Cache struct {
	cache *ristretto.Cache[string, CacheValue]
	ttl   time.Duration
}

func (c *Cache) Close() {
	c.cache.Close()
}

func (c *Cache) Set(domain string, qtype uint16, msg *dns.Msg) {
	ok := c.cache.SetWithTTL(fmt.Sprintf("%s-%d", domain, qtype), CacheValue{
		M: msg,
		T: time.Now().Unix(),
	}, 1, c.ttl)
	if !ok {
		slog.Warn("cache set failed", "domain", domain, "qtype", qtype)
	}
}

func (c *Cache) Get(domain string, qtype uint16) (CacheValue, bool) {
	return c.cache.Get(fmt.Sprintf("%s-%d", domain, qtype))
}

func (c *Cache) Del(domain string, qtype uint16) {
	c.cache.Del(fmt.Sprintf("%s-%d", domain, qtype))
}

func NewCache(maxCounters, maxCost, bufferItems int64, ttl time.Duration) (*Cache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, CacheValue]{
		NumCounters: maxCounters, // number of keys to track frequency of (10M).
		MaxCost:     maxCost,     // maximum cost of cache (1GB).
		BufferItems: bufferItems, // number of keys per Get buffer.
	})
	if err != nil {
		return nil, err
	}
	return &Cache{
		cache: cache,
		ttl:   ttl,
	}, nil
}
