# OpenGFW 主控 + Agent 分布式改造设计

本文基于当前仓库代码，给出一版面向前期落地的分布式改造设计。目标不是把 OpenGFW 直接改成“大而全”的安全平台，而是在保留现有高性能数据面能力的前提下，补出控制面、节点管理、策略下发、数据上报和基础分析报表能力。

## 1. 目标

前期版本聚焦以下四项能力：

1. 主控 + agent 形态，主控能够配置节点并完成程序下发。
2. 主控能够管理 agent 策略，规则下发并生效。
3. agent 能够本地执行规则、抓取流量特征并批量上报。
4. 主控能够收集流量数据并提供基础分析报表。

同时满足以下原则：

- 保留当前 `engine/`、`analyzer/`、`ruleset/`、`io/` 的核心处理链路。
- 所有流量判定必须在 agent 本地完成，不依赖主控做逐流远程裁决。
- 主控负责“管理、编排、分析”，agent 负责“执行、采集、上报”。
- 前期先做单主控架构，预留后续横向扩展能力。

## 2. 当前代码基础与可复用能力

当前仓库已经具备分布式改造所需的数据面基础。

### 2.1 可直接复用的能力

- 本地高性能流量处理链路：
  - [`engine/`](../engine) 负责 worker、TCP/UDP 流处理、规则匹配。
  - [`io/`](../io) 当前用 NFQUEUE 接入，适合网关或主机侧内联部署。
- 协议分析能力：
  - 已有 HTTP、TLS、DNS、QUIC、SSH、SOCKS、WireGuard、OpenVPN、FET、Trojan 等分析器。
  - 这些能力可直接作为主控分析报表的数据来源。
- 规则编译和热更新：
  - [`ruleset/expr.go`](../ruleset/expr.go) 已支持规则编译。
  - [`engine.Engine`](../engine/interface.go) 已支持 `UpdateRuleset` 运行时替换规则集。
- 流量事件钩子：
  - [`engine.Logger`](../engine/interface.go) 和 [`ruleset.Logger`](../ruleset/interface.go) 已覆盖流创建、属性更新、动作命中、规则命中、分析器日志等关键节点。

### 2.2 当前代码的缺口

- 当前只有单机 CLI 入口 [`cmd/root.go`](../cmd/root.go)。
- 配置和规则来自本地 YAML 文件，不具备远程控制面。
- 没有节点注册、认证、策略版本、回滚、升级、任务分发能力。
- 没有统一事件模型、批量上报、落盘缓冲、分析存储。
- 没有“仅为观测而启用分析器”的机制。

最后一点非常关键：当前分析器启用依赖规则表达式中是否引用对应字段。如果主控要做流量分析报表，不能只靠拦截规则间接启用分析器，必须补一层“遥测策略”。

## 3. 总体架构

### 3.1 架构分层

系统拆分为两层：

- 数据面：运行在 agent 上，负责流量捕获、协议分析、本地规则执行、本地聚合。
- 控制面：运行在主控上，负责节点管理、程序发布、策略管理、数据接收、分析报表。

### 3.2 逻辑架构

```text
+---------------------------+        +----------------------------------+
|          Master           |        |              Agent               |
|                           |        |                                  |
|  Node Manager             |<------>|  Control Client                  |
|  Release Manager          |        |  Task Executor                   |
|  Policy / Rules Manager   |        |  Local Bundle Cache              |
|  Config Compiler          |        |                                  |
|  Ingest Gateway           |<------>|  Event / Metric Uploader         |
|  Event Store              |        |  Event Aggregator                |
|  Report Service           |        |                                  |
|  Web API / UI             |        |  OpenGFW Runtime                 |
|                           |        |  - io/                           |
|                           |        |  - engine/                       |
|                           |        |  - analyzer/                     |
|                           |        |  - ruleset/                      |
+---------------------------+        +----------------------------------+
```

### 3.3 通信原则

- 所有控制连接由 agent 主动发起，避免 NAT、防火墙和边界网络导致主控反连失败。
- “主控下发”在实现上采用“主控创建任务，agent 心跳或长连接拉取任务”的方式。
- 程序升级、策略更新、证书轮换都走同一套任务通道。
- 流量数据上报采用批量、压缩、可重试的异步通道，避免影响本地判定链路。

## 4. 目标形态下的模块拆分

建议保留现有数据面目录，并新增以下模块：

```text
cmd/
  opengfw-agent/
  opengfw-master/

agent/
  runtime/
  control/
  bundle/
  report/
  state/

master/
  api/
  node/
  release/
  policy/
  ingest/
  report/
  auth/

pkg/
  models/
  bundle/
  transport/
  telemetry/
```

### 4.1 agent 侧模块

#### `agent/runtime`

职责：

- 包装现有 `engine` 启动逻辑。
- 把当前 [`cmd/root.go`](../cmd/root.go) 中一次性启动逻辑重构为可复用运行时。
- 支持“加载本地缓存 bundle 启动”和“运行时替换 bundle”。

建议抽象：

```go
type Runtime interface {
    Start(ctx context.Context) error
    ApplyBundle(ctx context.Context, bundle ActiveBundle) error
    Status() RuntimeStatus
}
```

#### `agent/control`

职责：

- 节点注册。
- 周期心跳。
- 拉取任务。
- 执行升级、配置更新、策略发布、证书更新。

#### `agent/bundle`

职责：

- 管理主控下发的配置包。
- 校验签名、校验和、版本号。
- 维护当前生效版本、上一个稳定版本、回滚点。

#### `agent/report`

职责：

- 接收来自 `engine.Logger`、`ruleset.Logger` 的事件。
- 做本地批量聚合、压缩、采样、节流。
- 上报原始事件和分钟级统计。

#### `agent/state`

职责：

- 持久化节点身份、证书、本地 bundle、待发送事件、失败重试队列。
- 建议前期使用本地目录加 WAL 文件；后续可切换到 SQLite/Bbolt。

### 4.2 主控侧模块

#### `master/node`

职责：

- 节点资产管理。
- 节点状态、标签、版本、在线状态维护。
- 首次安装和后续升级任务编排。

#### `master/release`

职责：

- 管理 agent 程序包。
- 生成升级任务。
- 支持灰度升级、分组升级、回滚。

#### `master/policy`

职责：

- 管理策略模板、规则集、遥测策略、节点组绑定关系。
- 发布 bundle 版本。
- 跟踪 agent 应用结果。

#### `master/ingest`

职责：

- 接收 agent 的事件和统计。
- 批量写入分析存储。
- 做基础清洗、归一化、字段补全。

#### `master/report`

职责：

- 生成流量概览、规则命中、可疑流量、恶意 IOC 命中等报表。
- 提供查询 API。

#### `master/api`

职责：

- 提供 Web UI 和 API 所需接口。
- 管理节点、策略、报表、任务、版本。

## 5. 关键设计决定

### 5.1 保留本地判定，不做远程裁决

原因：

- 当前 OpenGFW 的 NFQUEUE 处理是内联路径，远程裁决会直接引入时延和单点风险。
- 即使主控不可用，agent 仍然必须能继续执行最近一次稳定策略。
- 主控的角色应是“控制”和“分析”，不是“参与每个包的实时判定”。

### 5.2 程序下发采用“两阶段安装”

要满足“主控直接配置节点并下发程序”，前期建议分两种路径：

#### 首次安装

- 主控保存节点连接信息，如 SSH 地址、端口、凭据或密钥。
- 主控通过 SSH 将 agent 二进制、systemd service 文件、bootstrap token 下发到目标节点。
- 启动 agent 后，agent 使用 bootstrap token 向主控注册。

这是因为“没有 agent 时无法通过 agent 通道升级”，必须有一个初始引导手段。

#### 后续升级

- 主控发布新的 agent 版本。
- 在线 agent 通过控制通道收到升级任务。
- agent 下载带签名的程序包，校验后替换本地二进制并平滑重启。

这样既满足“主控直接配置节点”，也符合后续规模化运维。

### 5.3 新增“策略包 Bundle”概念

前期所有下发内容统一封装为一个 bundle，避免把多个配置项散落在不同接口。

建议 bundle 结构：

```yaml
bundleVersion: "2026-04-22T12:00:00Z"
agentVersion: "0.1.0"
runtime:
  io:
    queueSize: 128
    rcvBuf: 0
    sndBuf: 0
    local: false
    rst: false
  workers:
    count: 0
    queueSize: 64
    tcpMaxBufferedPagesTotal: 4096
    tcpMaxBufferedPagesPerConn: 64
    udpMaxStreams: 4096
telemetry:
  analyzers:
    - dns
    - tls
    - http
    - quic
    - fet
    - trojan
  events:
    ruleHit: true
    suspiciousOnly: false
    flowSummary: true
  sampling:
    benignFlow: 0.05
rules:
  - name: block-ads-by-sni
    action: block
    expr: tls.req.sni != nil && geosite(tls.req.sni, "category-ads-all")
  - name: suspicious-fet
    log: true
    expr: fet.yes == true
```

其中：

- `runtime` 对应现有 `cliConfig` 中的运行参数。
- `rules` 对应现有规则 YAML。
- `telemetry` 是新增概念，用于控制“观察哪些协议、上报哪些事件、采样率多少”。

### 5.4 新增“遥测策略”而不是把一切都做成规则

当前规则系统适合做“判定”，不适合直接承担全部“观测配置”。

例如：

- 想做 TLS SNI 报表，不代表一定要有一条依赖 `tls.req.sni` 的拦截规则。
- 想统计 DNS 问题域名 TopN，也不代表必须先写一条 DNS 规则。

因此建议新增独立的遥测策略：

- 指定必须启用哪些分析器。
- 指定哪些事件需要原始上报。
- 指定哪些维度需要分钟级聚合。
- 指定 benign 流量采样比例。

在实现上，可在 `ruleset` 之外增加一个 `TelemetryProfile`，由 agent runtime 在创建流时决定启用哪些分析器。

## 6. 对现有代码的具体改造点

### 6.1 启动入口重构

当前入口 [`cmd/root.go`](../cmd/root.go) 直接负责：

- 读取本地配置。
- 读取规则文件。
- 初始化 logger。
- 编译规则。
- 启动 engine。
- 处理 `SIGHUP` 热更新。

需要拆为两层：

- `agent/runtime`：提供可编程的启动和切换能力。
- `cmd/opengfw-agent`：仅做命令行参数、日志、状态目录、初始配置处理。

### 6.2 `engine.Logger` 改造成事件总线入口

当前 `engine.Logger` 与 `ruleset.Logger` 只是输出日志。前期应替换为“日志 + 事件”的双写实现。

建议增加：

```go
type EventSink interface {
    Emit(Event)
}

type CompositeRuntimeLogger struct {
    Log   *zap.Logger
    Sink  EventSink
}
```

需要接入的事件包括：

- 新建 TCP/UDP 流。
- 流属性更新。
- 流动作结果。
- 规则命中。
- 修改失败。
- 分析器错误。

### 6.3 新增流量事件模型

建议定义统一事件结构：

```go
type TrafficEvent struct {
    EventID      string
    AgentID      string
    Time         time.Time
    Type         string
    StreamID     int64
    Proto        string
    SrcIP        string
    DstIP        string
    SrcPort      uint16
    DstPort      uint16
    RuleName     string
    Action       string
    Props        map[string]any
    Suspicion    int
    Tags         []string
    BundleVer    string
}
```

事件类型前期建议控制在以下范围：

- `rule_hit`
- `stream_action`
- `suspicious_flow`
- `analyzer_error`
- `agent_status`

不建议前期对所有 `PropUpdate` 逐条原样上报，否则数据量会非常大。

### 6.4 新增本地聚合器

agent 不应把所有数据逐条直传主控，而应在本地聚合出分钟级指标。

建议聚合维度：

- 按节点、协议、动作的流量计数。
- 按规则的命中次数。
- 按 DNS 问题域名的 TopN。
- 按 TLS SNI 的 TopN。
- 按 HTTP Host / Path 的 TopN。
- 按 `fet.yes`、`trojan.yes` 的可疑命中数。

建议 agent 每 10 秒到 30 秒批量上报一次，分钟级报表则由主控继续汇总。

### 6.5 新增 bundle 应用与回滚机制

前期 agent 必须支持：

- 拉取新 bundle。
- 在本地校验。
- 先编译规则再切换。
- 应用失败自动保留旧版本。
- 应用成功后回报状态。

这部分可以直接复用现有 `ruleset.CompileExprRules` 和 `engine.UpdateRuleset`。

## 7. 主控与 agent 的协议设计

### 7.1 控制协议

前期建议使用 gRPC 或 HTTPS + JSON，两者都可行。

如果偏重开发速度：

- 用 HTTPS + JSON。

如果偏重长连接、任务推送、压缩效率：

- 用 gRPC。

前期推荐：

- 控制通道：gRPC 双向流。
- Web API：REST。
- 大对象下载：HTTPS 文件下载。

### 7.2 控制面主要消息

#### AgentRegister

用于首次注册：

- bootstrap token
- 主机名
- agent 版本
- 内核信息
- 是否具备 `CAP_NET_ADMIN`
- 节点标签和 IP

#### AgentHeartbeat

用于在线保活：

- agent 当前状态
- bundle 版本
- 流量处理状态
- 缓冲队列长度
- 最近错误

#### TaskDispatch

主控下发任务：

- 安装/升级 agent
- 更新 bundle
- 重启 agent
- 回滚 bundle
- 轮换证书

#### TaskResult

agent 回报任务执行结果：

- 成功/失败
- 生效版本
- 错误信息
- 执行时间

### 7.3 上报协议

建议拆成两类：

- 原始事件批次 `EventBatch`
- 聚合统计批次 `MetricBatch`

都支持：

- gzip/zstd 压缩
- ACK
- 重试
- 幂等批次 ID

## 8. 主控存储设计

### 8.1 元数据存储

建议使用 PostgreSQL，存储：

- 节点信息
- 节点分组
- agent 版本
- 策略和规则版本
- 发布记录
- 任务执行记录
- 用户与权限

### 8.2 事件与报表存储

建议前期使用 ClickHouse 存储流量事件和聚合结果。

原因：

- 流量事件天然偏时序和聚合查询。
- 需要高效支持 TopN、时间窗口、维度下钻。
- 后续报表扩展空间更好。

前期表设计建议：

- `traffic_event`
- `traffic_metric_1m`
- `rule_hit_1m`
- `dns_top_1m`
- `tls_sni_top_1m`
- `http_host_top_1m`
- `suspicious_1m`

如果前期资源受限，也可以先不存全部原始事件，仅保存：

- 规则命中事件
- 可疑流量事件
- 分钟级聚合

### 8.3 程序包和 bundle 存储

建议存到对象存储或主控本地文件仓库：

- agent 安装包
- agent 升级包
- bundle JSON/YAML
- 签名和校验和文件

## 9. 前期可交付的主控功能

### 9.1 节点管理

必须支持：

- 新增节点。
- 录入 SSH 引导信息。
- 首次安装 agent。
- 查看节点在线状态、版本、最近心跳时间。
- 节点打标签和分组。

前期不做：

- 多租户。
- 自动拓扑发现。
- 主机资产指纹识别。

### 9.2 程序发布

必须支持：

- 上传 agent 程序包。
- 按节点或节点组下发升级任务。
- 查看升级进度和结果。
- 失败回滚到上一稳定版本。

### 9.3 策略和规则管理

必须支持：

- 图形化或文本方式维护规则。
- 在主控侧做规则编译校验。
- 生成 bundle 版本。
- 按节点组发布。
- 查看节点应用成功率。
- 一键回滚到历史 bundle。

### 9.4 数据接收与分析报表

前期报表建议只做高价值、低复杂度的内容：

- 节点流量概览：
  - 总流数、协议分布、放行/阻断/丢弃数。
- 规则命中报表：
  - 按规则统计命中次数、命中节点、时间趋势。
- DNS 分析报表：
  - Top 查询域名、Top 响应码、异常域名。
- TLS 分析报表：
  - Top SNI、ALPN 分布、可疑 TLS 流。
- HTTP 分析报表：
  - Top Host、状态码分布、可疑路径。
- 可疑流量报表：
  - `fet.yes`、`trojan.yes`、SOCKS、OpenVPN、WireGuard、QUIC 可疑流量趋势。

## 10. agent 前期行为设计

### 10.1 启动流程

```text
读取本地状态目录
  -> 加载最近稳定 bundle
  -> 启动 OpenGFW runtime
  -> 建立到主控的控制连接
  -> 完成注册/心跳
  -> 拉取待执行任务
  -> 持续上报事件和统计
```

即使主控不可用，agent 仍应使用本地最近一次稳定 bundle 继续运行。

### 10.2 策略应用流程

```text
收到 bundle 更新任务
  -> 下载 bundle
  -> 校验签名和版本
  -> 本地编译规则
  -> 更新 runtime
  -> 切换 active bundle
  -> 上报成功/失败
```

### 10.3 数据上报流程

```text
engine / ruleset 事件
  -> 写入本地聚合器
  -> 聚合出 EventBatch / MetricBatch
  -> 异步上传
  -> 主控 ACK
  -> 本地删除已确认批次
```

主控不可用时：

- 先落本地待发送队列。
- 达到磁盘上限后优先丢弃低价值 benign 原始事件。
- 高价值事件如 `rule_hit`、`suspicious_flow` 尽量保留。

## 11. 恶意流量分析能力在前期版本中的落点

在此前提下，前期可以实现一版有实际价值的网络侧恶意流量分析。

### 11.1 可直接实现的能力

- IOC 型检测：
  - 域名、SNI、IP、HTTP Host、路径规则匹配。
- 协议和隧道识别：
  - SOCKS、Trojan、WireGuard、OpenVPN、QUIC、FET。
- 行为告警：
  - 某规则高频命中。
  - 某节点出现大量可疑加密流。
  - 某域名短时间内在多个节点同时命中。
- 汇总报表：
  - 可疑流量趋势、节点分布、规则分布。

### 11.2 前期不承诺的能力

- 载荷级深度解密分析。
- 主机进程归因。
- 文件落地和沙箱联动。
- 复杂机器学习模型分类。

这部分不影响前期目标完成，应在后续版本再扩展。

## 12. 建议的数据模型

### 12.1 节点

```text
AgentNode
- id
- name
- hostname
- management_ip
- labels
- status
- agent_version
- bundle_version
- last_seen_at
- capabilities
```

### 12.2 策略

```text
PolicyBundle
- id
- version
- target_selector
- runtime_config
- telemetry_profile
- rule_set
- status
- created_at
- created_by
```

### 12.3 任务

```text
Task
- id
- type
- target_agent_id
- payload
- status
- created_at
- started_at
- finished_at
- error_message
```

### 12.4 事件

```text
TrafficEvent
- event_id
- agent_id
- timestamp
- event_type
- protocol
- src_ip
- dst_ip
- src_port
- dst_port
- rule_name
- action
- props
- suspicion_score
- tags
```

## 13. 分阶段实施建议

### Phase 1：单节点可控化

目标：

- 把当前 CLI 重构成 agent runtime。
- 支持本地 bundle 启动。
- 支持主控注册、心跳、任务拉取。
- 支持主控通过 SSH 完成首次安装。

交付物：

- `opengfw-agent`
- `opengfw-master`
- 节点注册和基础任务通道

### Phase 2：策略发布

目标：

- 主控管理规则和遥测策略。
- 主控侧编译校验规则。
- 生成 bundle 并下发。
- agent 运行时更新生效并回报结果。

交付物：

- bundle 模型
- 发布与回滚
- 节点组绑定

### Phase 3：事件上报与基础报表

目标：

- agent 事件批量上报。
- 主控入库。
- 生成基础流量概览、规则命中、DNS/TLS/HTTP 报表。

交付物：

- ingest 通道
- 聚合任务
- 报表查询 API

### Phase 4：可疑流量专题分析

目标：

- 加入 IOC 管理。
- 输出可疑流量专题报表。
- 节点、域名、规则三维交叉分析。

交付物：

- IOC 数据管理
- 可疑流量工作台
- 联动查询

## 14. 前期版本的范围控制建议

为了确保方案能落地，前期建议严格控制以下范围：

- 只支持单主控部署。
- 只支持 Linux agent。
- 首次安装仅支持 SSH 引导。
- 主控先做 API + 基础页面，不追求完整前端平台。
- 报表先做分钟级聚合和少量高价值原始事件，不做全量原始流回放。
- 不在第一期引入复杂告警编排和多租户权限模型。

## 15. 主要风险与应对

### 15.1 数据量过大

风险：

- 如果原样上报所有流属性更新，主控存储和带宽都会过载。

应对：

- 默认仅上报规则命中、可疑流量和聚合数据。
- benign 流量按采样上报。
- 主控只保留必要的明细和分钟级统计。

### 15.2 规则与观测耦合过深

风险：

- 如果仍然只靠规则启用分析器，报表会受到规则设计制约。

应对：

- 明确引入 `telemetry` 配置，独立控制分析器启用。

### 15.3 升级失败导致 agent 不可用

风险：

- 远程升级时二进制替换失败或规则编译失败。

应对：

- 保留最近稳定版本。
- 升级和 bundle 发布都支持自动回滚。
- 任务结果必须带错误上下文。

### 15.4 主控不可用

风险：

- 影响策略发布、上报和报表。

应对：

- agent 持续使用本地稳定 bundle。
- 本地缓存待上报数据。
- 恢复后继续补传。

## 16. 结论

基于当前 OpenGFW 代码，做一套“主控负责管理和分析，agent 本地执行并上报”的系统是可行的，而且前期可以较快落地。

最关键的改造点只有三类：

1. 把当前单机 CLI 重构成可热更新的 agent runtime。
2. 在现有 `engine.Logger` / `ruleset.Logger` 之上补出事件总线、本地聚合和上报通道。
3. 在主控侧建立节点管理、bundle 发布、事件接收和基础报表能力。

按本文设计推进，前期版本可以完成你要求的四项核心目标，并且为后续恶意流量分析、IOC 联动、灰度发布和多节点关联分析留出清晰扩展路径。
