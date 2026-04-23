# OpenGFW 项目说明与使用文档

本文基于当前仓库源码梳理，目标是把项目定位、运行原理、目录结构、配置方式和规则写法一次讲清楚，便于首次部署和后续二次开发。

## 1. 项目定位

OpenGFW 是一个运行在 Linux 上的开源网络过滤与流量分析程序。当前实现以 NFQUEUE 作为唯一的 I/O 后端，把经过内核 Netfilter 的数据包送入用户态，再完成协议分析、规则匹配和放行/阻断/修改。

它的核心能力可以概括为四件事：

1. 对 TCP 做重组，对 UDP 做流级管理。
2. 从多种协议中提取属性，供规则表达式使用。
3. 用表达式规则决定 `allow`、`block`、`drop`、`modify`。
4. 通过连接标记对整条流做 offload，减少重复判定。

## 2. 整体运行链路

一次完整处理链路如下：

1. [`main.go`](/root/OpenGFW/main.go) 启动 CLI。
2. [`cmd/root.go`](/root/OpenGFW/cmd/root.go) 读取配置文件、初始化日志、加载规则文件。
3. [`io/nfqueue.go`](/root/OpenGFW/io/nfqueue.go) 打开 NFQUEUE 100，并自动安装 nftables 或 iptables 规则。
4. [`engine/engine.go`](/root/OpenGFW/engine/engine.go) 依据 conntrack stream ID 把流分发到不同 worker。
5. [`engine/tcp.go`](/root/OpenGFW/engine/tcp.go) 负责 TCP 重组；[`engine/udp.go`](/root/OpenGFW/engine/udp.go) 负责 UDP 流跟踪。
6. [`analyzer/`](/root/OpenGFW/analyzer) 下的分析器从流量中提取协议属性。
7. [`ruleset/expr.go`](/root/OpenGFW/ruleset/expr.go) 用 `expr` 表达式引擎匹配规则，返回动作与可选 modifier。
8. [`io/nfqueue.go`](/root/OpenGFW/io/nfqueue.go) 把 verdict 回写内核；对已确定结果的流打 connmark，后续包直接放行或丢弃。

## 3. 仓库结构

- [`main.go`](/root/OpenGFW/main.go)：程序入口。
- [`cmd/`](/root/OpenGFW/cmd)：CLI、配置读取、日志初始化、规则热重载。
- [`engine/`](/root/OpenGFW/engine)：worker、TCP/UDP 处理、规则分发。
- [`io/`](/root/OpenGFW/io)：I/O 抽象层与 NFQUEUE 实现。
- [`analyzer/`](/root/OpenGFW/analyzer)：协议分析器与通用工具。
- [`modifier/`](/root/OpenGFW/modifier)：报文修改器，目前只有 DNS。
- [`ruleset/`](/root/OpenGFW/ruleset)：规则 YAML 解析、表达式编译、内置函数、Geo 匹配。
- [`docs/`](/root/OpenGFW/docs)：项目文档与示例文件。
- [`.github/workflows/`](/root/OpenGFW/.github/workflows)：CI 检查与发布流程。

## 4. 当前能力

### 4.1 分析器

源码中已注册的分析器在 [`cmd/root.go`](/root/OpenGFW/cmd/root.go)。

- TCP：`fet`、`http`、`socks`、`ssh`、`tls`、`trojan`
- TCP/UDP：`dns`、`openvpn`
- UDP：`quic`、`wireguard`

常见可用属性示例：

- `http.req.method`、`http.req.path`、`http.req.headers.host`
- `http.resp.status`
- `tls.req.sni`、`tls.req.alpn`、`tls.req.supported_versions`
- `tls.resp.cipher`
- `dns.qr`、`dns.questions`、`dns.answers`
- `ssh.client.software`、`ssh.server.software`
- `fet.yes`
- `trojan.yes`
- `openvpn.rx_pkt_cnt`、`openvpn.tx_pkt_cnt`
- `wireguard.message_type`
- `quic.req.sni`

说明：

- 不是每个分析器都只支持一个方向，像 `http`、`tls` 会分别写入 `req` 和 `resp`。
- HTTP Header 在源码里会被统一转成小写键名。
- 规则里只有真正引用到的分析器才会被启用，这是 [`ruleset/expr.go`](/root/OpenGFW/ruleset/expr.go) 在编译阶段做的依赖裁剪。

### 4.2 动作

规则支持以下动作：

- `allow`：放行整条流，后续包直接 bypass。
- `block`：阻断整条流。
- `drop`：只丢当前包，主要对 UDP 有意义；对 TCP 可视为阻断整条流。
- `modify`：修改当前 UDP 包；当前仓库只有 DNS UDP modifier。对 TCP 规则来说，这个动作没有实际改包效果。

### 4.3 Modifier

当前只注册了一个 modifier：

- `dns`：见 [`modifier/udp/dns.go`](/root/OpenGFW/modifier/udp/dns.go)

支持参数：

- `a`：把 A 记录改写为指定 IPv4
- `aaaa`：把 AAAA 记录改写为指定 IPv6

## 5. 环境要求

### 5.1 运行环境

- Linux
- 具备 Netfilter/NFQUEUE 支持的内核
- root 权限，或等效的 `CAP_NET_ADMIN`/防火墙控制能力
- 建议安装 `nft`；如果系统里找不到 `nft`，程序会退回到 iptables

### 5.2 构建环境

- Go 1.26 及以上
- 建议使用 Go 1.26.2，与项目当前 toolchain 和发布工作流保持一致

说明：

- [`go.mod`](/root/OpenGFW/go.mod) 声明的是 `go 1.26.0`
- [`go.mod`](/root/OpenGFW/go.mod) 额外指定了 `toolchain go1.26.2`
- 发布工作流 [`release.yaml`](/root/OpenGFW/.github/workflows/release.yaml) 使用的是 Go 1.26.2
- CI 工作流 [`check.yaml`](/root/OpenGFW/.github/workflows/check.yaml) 会执行 `go vet ./...` 和 `go test ./...`

## 6. 快速开始

### 6.1 编译

```bash
go build -o OpenGFW .
```

### 6.2 准备配置

仓库里已经补了一套可直接参考的示例：

- 配置文件：[`docs/examples/config.yaml`](/root/OpenGFW/docs/examples/config.yaml)
- 规则文件：[`docs/examples/rules.yaml`](/root/OpenGFW/docs/examples/rules.yaml)

### 6.3 启动

```bash
sudo ./OpenGFW -c docs/examples/config.yaml docs/examples/rules.yaml
```

命令格式来自 [`cmd/root.go`](/root/OpenGFW/cmd/root.go)：

```text
OpenGFW [flags] rule_file
```

常用参数：

- `-c, --config`：指定配置文件
- `-l, --log-level`：`debug`、`info`、`warn`、`error`
- `-f, --log-format`：`console`、`json`

也支持两个环境变量：

- `OPENGFW_LOG_LEVEL`
- `OPENGFW_LOG_FORMAT`

### 6.4 热重载规则

运行中给进程发送 `SIGHUP`，程序会重新读取规则文件并更新 ruleset：

```bash
sudo kill -HUP <pid>
```

注意：

- 这里热重载的只有 `rule_file`
- 配置文件 `config.yaml` 不会随 `SIGHUP` 重新读取

## 7. 配置文件说明

配置结构定义在 [`cmd/root.go`](/root/OpenGFW/cmd/root.go)。

如果没有传 `-c`，程序会按以下顺序寻找配置文件：

1. 当前目录下的 `config.yaml` 或 `config.yml`
2. `$HOME/.opengfw/config.yaml` 或 `config.yml`
3. `/etc/opengfw/config.yaml` 或 `config.yml`

### 7.1 `io`

```yaml
io:
  queueSize: 128
  rcvBuf: 0
  sndBuf: 0
  local: false
  rst: false
```

- `queueSize`：NFQUEUE 队列长度；为 `0` 时默认 `128`
- `rcvBuf`：netlink 读缓冲；为 `0` 时使用系统/库默认值
- `sndBuf`：netlink 写缓冲；为 `0` 时使用系统/库默认值
- `local`：
  - `false`：处理 `FORWARD` 链流量，适合网关/路由场景
  - `true`：处理 `INPUT` 和 `OUTPUT`，适合本机流量
- `rst`：
  - `false`：阻断 TCP 时直接 drop
  - `true`：对被阻断 TCP 流返回 `tcp reset`
  - 限制：`local: true` 时不能开启 `rst`

补充说明：

- 程序会优先安装 nftables 规则，表名固定为 `inet opengfw`
- 如果没有 `nft`，则自动回退到 iptables
- NFQUEUE 规则带 `queue-bypass`，用户态程序不在时，流量不会因为排队失败被一刀切阻断

### 7.2 `workers`

```yaml
workers:
  count: 0
  queueSize: 64
  tcpMaxBufferedPagesTotal: 4096
  tcpMaxBufferedPagesPerConn: 64
  udpMaxStreams: 4096
```

- `count`：worker 数；小于等于 `0` 时自动取 CPU 核数
- `queueSize`：每个 worker 的包队列长度；默认 `64`
- `tcpMaxBufferedPagesTotal`：TCP 总重组缓冲页上限；默认 `4096`
- `tcpMaxBufferedPagesPerConn`：单 TCP 连接重组缓冲页上限；默认 `64`
- `udpMaxStreams`：UDP 流缓存上限；默认 `4096`

### 7.3 `ruleset`

```yaml
ruleset:
  geoip: ""
  geosite: ""
```

- `geoip`：GeoIP 数据文件路径
- `geosite`：GeoSite 数据文件路径

当这两个字段为空，且规则里实际使用了 `geoip()` / `geosite()` 时：

- 程序会尝试自动下载 `geoip.dat` / `geosite.dat`
- 下载目标是当前工作目录
- 文件存在但超过默认更新时间时，也可能触发更新

如果你不希望程序在运行时自动下载数据，直接把这两个路径显式配好。

## 8. 规则文件说明

规则文件是一个 YAML 数组，由 [`ruleset/expr.go`](/root/OpenGFW/ruleset/expr.go) 读取和编译。

基本结构如下：

```yaml
- name: block-example
  action: block
  log: true
  expr: tls.req.sni == "example.com"

- name: rewrite-dns
  action: modify
  modifier:
    name: dns
    args:
      a: 127.0.0.1
      aaaa: "::1"
  expr: proto == "udp" && dns.qr == true
```

字段说明：

- `name`：规则名称，用于日志
- `action`：`allow`、`block`、`drop`、`modify`
- `log`：命中时打印 ruleset log
- `modifier`：只在 `action: modify` 时生效
- `expr`：expr 表达式

约束与行为：

- 每条规则至少要有 `action` 或 `log` 之一
- 规则按顺序匹配
- 第一条命中的“带 action 的规则”会立刻返回结果
- 只有 `log: true` 但没有 `action` 的规则会继续往后匹配

### 8.1 表达式环境

规则里可直接使用以下内置字段：

- `id`
- `proto`：`"tcp"` 或 `"udp"`
- `ip.src`、`ip.dst`
- `port.src`、`port.dst`

还可以使用分析器属性，例如：

- `http.req.method == "CONNECT"`
- `http.req.headers.host == "example.com"`
- `tls.req.sni == "example.com"`
- `dns.qr == false`
- `fet.yes == true`

### 8.2 内置函数

内置函数同样定义在 [`ruleset/expr.go`](/root/OpenGFW/ruleset/expr.go)：

- `cidr(ip, "192.168.0.0/16")`
- `geoip(ip, "cn")`
- `geosite(host, "category-ads-all")`
- `lookup(host)`
- `lookup(host, "1.1.1.1:53")`

注意：

- `lookup()` 会用受保护的连接去做 DNS 解析，避免查询流量再次被自己抓回 NFQUEUE
- 只有规则里实际引用到 `geoip()` 或 `geosite()` 时，相关 Geo 数据才会加载/下载

### 8.3 常见规则示例

#### 放行内网地址

```yaml
- name: allow-lan
  action: allow
  expr: cidr(ip.src, "192.168.0.0/16") || cidr(ip.dst, "192.168.0.0/16")
```

#### 记录所有带 SNI 的 TLS 流

```yaml
- name: log-tls-sni
  log: true
  expr: tls.req.sni != nil
```

#### 按 GeoSite 阻断广告域名

```yaml
- name: block-ads-by-sni
  action: block
  expr: tls.req.sni != nil && geosite(tls.req.sni, "category-ads-all")
```

#### 阻断疑似全加密代理流量

```yaml
- name: block-fet
  action: block
  expr: fet.yes == true
```

#### 改写 DNS 应答

```yaml
- name: rewrite-ads-dns
  action: modify
  modifier:
    name: dns
    args:
      a: 127.0.0.1
      aaaa: "::1"
  expr: proto == "udp" && dns.qr == true && dns.questions != nil && len(dns.questions) > 0 && dns.questions[0].name == "ads.example.com"
```

## 9. 示例文件

仓库已提供两份示例文件：

- [`docs/examples/config.yaml`](/root/OpenGFW/docs/examples/config.yaml)
- [`docs/examples/rules.yaml`](/root/OpenGFW/docs/examples/rules.yaml)

建议使用方式：

1. 复制到你自己的部署目录
2. 先只保留日志规则，确认属性提取是否符合预期
3. 再逐步增加 `block`、`drop`、`modify`

## 10. 调试与运维建议

- 首次上线先用 `-l debug` 观察 `TCP/UDP stream property update` 日志
- 规则命中日志来自 `log: true`
- 如果规则写错，表达式运行错误会记录为 `ruleset match error`
- 正常退出时程序会尝试删除自己安装的 nftables/iptables 规则
- 如果进程异常退出，建议人工检查 `inet opengfw` 表或相应 iptables 规则是否残留

## 11. 二次开发入口

### 11.1 新增分析器

实现以下接口之一：

- [`analyzer.TCPAnalyzer`](/root/OpenGFW/analyzer/interface.go)
- [`analyzer.UDPAnalyzer`](/root/OpenGFW/analyzer/interface.go)

然后把新分析器注册到 [`cmd/root.go`](/root/OpenGFW/cmd/root.go) 的 `analyzers` 列表。

### 11.2 新增 Modifier

实现：

- [`modifier.Modifier`](/root/OpenGFW/modifier/interface.go)

如果是 UDP modifier，还要实现：

- [`modifier.UDPModifierInstance`](/root/OpenGFW/modifier/interface.go)

最后注册到 [`cmd/root.go`](/root/OpenGFW/cmd/root.go) 的 `modifiers` 列表。

### 11.3 新增规则函数

在 [`ruleset/expr.go`](/root/OpenGFW/ruleset/expr.go) 的 `buildFunctionMap()` 中增加内置函数即可。

## 12. 已知限制

- 当前 I/O 后端只有 NFQUEUE，没有 pcap、XDP 或 eBPF 后端
- 当前发布工作流只构建 Linux 二进制
- `modify` 目前只覆盖 UDP DNS 改写
- `SIGHUP` 只重载规则文件，不重载配置文件
- Geo 数据自动下载依赖外网，并会写入当前工作目录
- 当前仓库没有随源码提供默认生产配置，需要自行按场景调整
