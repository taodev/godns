# godns
godns 是一个专注于本地快速解析、缓存与规则分流的高性能 DNS 代理服务器，支持自定义上游（如 UDP、TCP、DoH、DoT 等），可通过 geosite 进行分流
## 核心功能
- **多协议支持**：兼容 UDP、TCP、STCP（加密 TCP）、DoH（DNS over HTTPS）等上游协议，灵活适配不同网络环境。
- **智能分流**：通过 `geosite` 规则（如 `cn`、`google`、`github` 等）实现国内外域名精准分流，指定不同上游解析。
- **缓存优化**：支持自定义缓存大小、TTL 范围（最小/最大 TTL 覆盖），自动异步刷新过期缓存，提升解析速度。
- **请求重写**：通过配置规则重写特定域名的 DNS 响应（如 A/AAAA/CNAME/TXT 记录），满足本地开发或测试需求。
- **IPv6 过滤**：可全局禁用 AAAA 记录响应，避免 IPv6 解析问题（如网络链路不稳定时）。
- **多服务端支持**：内置 UDP、TCP、STCP、DoH 服务端，支持同时监听多个协议端口。

## 快速安装
### Docker 部署（推荐）
```bash
# 拉取镜像
docker pull taodev/godns:latest

# 启动容器（挂载配置文件）
docker run -d \
  -p 53:53 \
  -p 443:443 \
  -v ./conf:/app/conf \
  --name godns \
  taodev/godns:latest
```
### github 仓库
```bash
# 拉取镜像
docker pull ghcr.io/taodev/godns:latest

# 启动容器（挂载配置文件）
docker run -d \
  -p 53:53 \
  -p 443:443 \
  -v ./conf:/app/conf \
  --name godns \
  taodev/godns:latest
```
### 源码构建
```bash
# 克隆项目
git clone https://github.com/taodev/godns.git
cd godns

# 构建二进制（需 Go 1.24+）
go build -o godns ./cmd/godns

# 启动服务（使用默认配置）
./godns -c ./conf/config.yaml
```

## 配置说明
核心配置文件为 [`conf/config.yaml`](./conf/config.yaml)，支持 YAML 格式，关键参数如下：
### 基础配置
```yaml
# 日志级别（debug/info/warn/error）
log-level: debug
# UDP 服务监听地址（默认端口 53）
udp: :53
# TCP 服务监听地址（可选）
tcp: :53
# 是否禁用 AAAA 记录（IPv6）
block-aaaa: true
# HTTPS 证书路径（可选，启用 TLS）
cert: conf/cert.pem
# HTTPS 私钥路径（可选）
key: conf/key.pem
# 自定义 GeoSite 路径（可选）
geosite: conf/geosite.dat
```
### STCP 服务（私有加密 TCP）
```yaml
stcp:
  # STCP 服务监听地址
  addr: :553
  # 通信密码（需与客户端一致）
  password: 123456
```
### DoH 服务（DNS over HTTPS）
```yaml
# DoH 服务监听地址
doh: :443
```
### Bootstrap DNS 服务器
```yaml
bootstrap-dns:
  - 223.5.5.5
  - 223.6.6.6
```
### 缓存配置
```yaml
cache:
  # 最大缓存条目数
  max-counters: 10000
  # 最大缓存成本（与条目大小相关）
  max-cost: 10000
  # 写缓存数量
  buffer-items: 64
  # 缓存默认 TTL
  ttl: 24h
  # 最小覆盖 TTL（秒）
  min-ttl: 60
  # 最大覆盖 TTL（秒）
  max-ttl: 86400
```
### 上游配置
```yaml
upstream:
  # UDP 上游（自动补全为 udp://223.5.5.5:53）
  alidns: 223.5.5.5
  # 支持域名（自动通过 bootstrap DNS 解析）
  googledns: dns.google
  # STCP 上游（密码:123456）
  mydns: stcp://123456@127.0.0.1:553
# 默认上游（未配置时使用第一个）
default-upstream: mydns
```
### 路由规则（支持 geosite）
```yaml
route:
  # 匹配后缀的域名使用 mydns
  - mydns(suffix("github.com"))
  # 阿里云相关域名使用 alidns
  - alidns(geosite("aliyun"), suffix("aliyun.com"))
  # GitHub/Google 域名使用 mydns
  - mydns(geosite("github", "google"))
  # 国内域名使用 alidns
  - alidns(geosite("cn"))
```
### 请求重写规则
```yaml
rewrite:
    # 目标域名
  - domain: test.example.com
    # 记录类型（A/AAAA/CNAME/TXT）
    type: A
    # 重写值（IP/CNAME/TXT内容）
    value: 127.0.0.1
    # 自定义 TTL（秒）
    ttl: 300
```

---
## 使用示例
### 基础 DNS 解析
配置 `udp: :53` 后，将系统 DNS 服务器设置为当前主机 IP，直接通过 `dig` 测试：
```bash
dig @127.0.0.1 google.com
```
### DoH 请求
通过 HTTPS 访问 DoH 服务（需启用 TLS）：
```bash
curl "https://127.0.0.1/dns-query?dns=$(base64url encode 'example.com 的 DNS 请求包')"
```
### STCP 客户端（加密通信）
使用支持 STCP 协议的客户端，配置服务地址 `127.0.0.1:553` 和密码 `123456`，发送加密 DNS 请求。

---
## 贡献与反馈
问题反馈：GitHub Issues
代码贡献：提交 Pull Request 前请先创建 [Issues](https://github.com/taodev/godns/issues) 讨论功能需求。
配置扩展：支持通过 geosite.dat 文件自定义分流规则（需下载或生成）。

---
## 许可证
MIT License，详见 [LICENSE](./LICENSE)。