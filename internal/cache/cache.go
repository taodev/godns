package cache

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/miekg/dns"
	"github.com/taodev/godns/internal/adapter"
	"github.com/taodev/godns/internal/utils"
)

type Options struct {
	// 最大缓存条目数
	MaxCounters int64 `yaml:"max-counters" default:"10000"`
	// 最大缓存成本（与条目大小相关）
	MaxCost int64 `yaml:"max-cost" default:"10000"`
	// 写缓存数量
	BufferItems int64 `yaml:"buffer-items" default:"64"`
	// 缓存默认 TTL
	TTL time.Duration `yaml:"ttl" default:"24h"`
	// 缓存线程数
	Threads int `yaml:"threads" default:"5"`
	// 重新请求 TTL
	RefreshTTL time.Duration `yaml:"refresh-ttl" default:"5m"`
}

type CacheValue struct {
	M        *dns.Msg
	ExpireAt int64
}

// 是否过期
func (cv CacheValue) IsExpired() bool {
	return time.Now().Unix() > cv.ExpireAt
}

type requestArgument struct {
	domain string
	qtype  uint16
}

type Cache struct {
	opts      *Options
	query     adapter.DnsQuery
	cache     *ristretto.Cache[string, CacheValue]
	wait      sync.WaitGroup
	requestCh chan *requestArgument
}

func New(opts *Options) (*Cache, error) {
	cache, err := ristretto.NewCache(&ristretto.Config[string, CacheValue]{
		NumCounters: opts.MaxCounters, // number of keys to track frequency of (10M).
		MaxCost:     opts.MaxCost,     // maximum cost of cache (1GB).
		BufferItems: opts.BufferItems, // number of keys per Get buffer.
	})
	if err != nil {
		return nil, err
	}
	return &Cache{
		opts:      opts,
		cache:     cache,
		requestCh: make(chan *requestArgument, 256),
	}, nil
}

func (c *Cache) SetQuery(query adapter.DnsQuery) {
	c.query = query
}

func (c *Cache) Start() (err error) {
	for i := 0; i < c.opts.Threads; i++ {
		c.wait.Add(1)
		go c.handleUpdate()
	}
	return
}

func (c *Cache) Close() {
	slog.Debug("cache close")
	close(c.requestCh)
	c.wait.Wait()
	c.cache.Close()
}

func (c *Cache) Set(domain string, qtype uint16, msg *dns.Msg) {
	ok := c.cache.SetWithTTL(fmt.Sprintf("%s-%d", domain, qtype), CacheValue{
		M:        msg.Copy(),
		ExpireAt: time.Now().Add(c.opts.RefreshTTL).Unix(),
	}, 1, c.opts.TTL)
	if !ok {
		slog.Warn("cache set failed", "domain", domain, "qtype", qtype)
	}
}

func (c *Cache) Get(domain string, qtype uint16) (CacheValue, bool) {
	return c.cache.Get(fmt.Sprintf("%s-%d", domain, qtype))
}

func (c *Cache) GetAndUpdate(domain string, qtype uint16) (CacheValue, bool) {
	cv, ok := c.Get(domain, qtype)
	if !ok {
		return cv, false
	}
	if cv.IsExpired() {
		// 更新
		c.requestCh <- &requestArgument{
			domain: domain,
			qtype:  qtype,
		}
	}
	return cv, true
}

func (c *Cache) Del(domain string, qtype uint16) {
	c.cache.Del(fmt.Sprintf("%s-%d", domain, qtype))
}

func (c *Cache) handleUpdate() {
	defer c.wait.Done()

	for {
		args, ok := <-c.requestCh
		if !ok {
			return
		}

		if c.query == nil {
			slog.Error("cache dnsQuery is nil")
			continue
		}

		// 从 outbound 获取
		req := new(dns.Msg)
		req.SetQuestion(args.domain, args.qtype)
		msg, _, err := c.query.Resolve(req)
		if err != nil {
			slog.Error("resolve failed", "domain", args.domain, "qtype", args.qtype, "error", err)
			continue
		}
		// 缓存
		c.Set(args.domain, args.qtype, msg)
		slog.Debug("cache update", "domain", args.domain, "qtype", args.qtype, "ttl", utils.GetMinTTL(msg))
	}
}
