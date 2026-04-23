const { createApp } = Vue;

const CHART_COLORS = {
  primary: "#2563eb",
  secondary: "#0ea5e9",
  success: "#16a34a",
  warning: "#d97706",
  danger: "#dc2626",
  slate: "#64748b",
  grid: "rgba(15, 23, 42, 0.08)",
  fill: "rgba(37, 99, 235, 0.12)",
};

const DEFAULT_REPORTING_BUNDLE_VERSION = "system-default-reporting";
const SESSION_TOKEN_KEY = "opengfw_session_token";
let runtimeSessionToken = "";

const VIEW_META = {
  overview: {
    title: "总览",
  },
  nodes: {
    title: "节点",
  },
  policies: {
    title: "策略",
  },
  releases: {
    title: "发布",
  },
  events: {
    title: "事件",
  },
};

const AVAILABLE_ANALYZERS = [
  "dns",
  "http",
  "tls",
  "ssh",
  "socks",
  "fet",
  "trojan",
  "quic",
  "wireguard",
  "openvpn",
];

const AGENT_BUILD_TARGETS = [
  { key: "linux-amd64", label: "Linux x86_64", goos: "linux", goarch: "amd64" },
  { key: "linux-arm64", label: "Linux ARM64", goos: "linux", goarch: "arm64" },
  { key: "linux-386", label: "Linux 386", goos: "linux", goarch: "386" },
];

const RULE_TEMPLATES = [
  {
    key: "allow-lan",
    label: "放行内网",
    description: "按 CIDR 放行内网源/目的地址",
    rule: {
      name: "allow-lan",
      action: "allow",
      log: false,
      expr: 'cidr(ip.src, "192.168.0.0/16") || cidr(ip.dst, "192.168.0.0/16")',
      modifierName: "",
      modifierArgsText: "",
    },
  },
  {
    key: "log-tls-sni",
    label: "记录 TLS SNI",
    description: "仅日志规则，不拦截",
    rule: {
      name: "log-tls-sni",
      action: "",
      log: true,
      expr: "tls.req.sni != nil",
      modifierName: "",
      modifierArgsText: "",
    },
  },
  {
    key: "block-ads-sni",
    label: "拦截广告域",
    description: "基于 GeoSite 阻断广告 SNI",
    rule: {
      name: "block-ads-by-sni",
      action: "block",
      log: false,
      expr: 'tls.req.sni != nil && geosite(tls.req.sni, "category-ads-all")',
      modifierName: "",
      modifierArgsText: "",
    },
  },
  {
    key: "block-fet",
    label: "阻断 FET",
    description: "拦截疑似全加密代理流量",
    rule: {
      name: "block-fet",
      action: "block",
      log: false,
      expr: "fet.yes == true",
      modifierName: "",
      modifierArgsText: "",
    },
  },
  {
    key: "rewrite-dns",
    label: "改写 DNS",
    description: "使用 dns modifier 修改应答",
    rule: {
      name: "rewrite-ads-dns",
      action: "modify",
      log: false,
      expr: 'proto == "udp" && dns.qr == true && dns.questions != nil && len(dns.questions) > 0 && dns.questions[0].name == "ads.example.com"',
      modifierName: "dns",
      modifierArgsText: prettyJson({ a: "127.0.0.1", aaaa: "::1" }),
    },
  },
];

const RULE_EXPR_SNIPPETS = [
  { label: "TCP", expr: 'proto == "tcp"' },
  { label: "UDP", expr: 'proto == "udp"' },
  { label: "TLS SNI", expr: "tls.req.sni != nil" },
  { label: "HTTP Host", expr: 'http.req.headers.host == "example.com"' },
  { label: "DNS Q", expr: "dns.questions != nil && len(dns.questions) > 0" },
  { label: "GeoSite", expr: 'geosite(tls.req.sni, "category-ads-all")' },
  { label: "CIDR", expr: 'cidr(ip.src, "192.168.0.0/16")' },
  { label: "FET", expr: "fet.yes == true" },
];

const RULE_FIELD_HINTS = [
  "proto",
  "ip.src / ip.dst",
  "port.src / port.dst",
  "http.req.method",
  "http.req.headers.host",
  "tls.req.sni",
  "dns.questions[0].name",
  "ssh.client.software",
  "quic.req.sni",
  "fet.yes / trojan.yes",
];

const RULE_ACTION_HELP = {
  "": "仅记录日志，命中后继续向下匹配后续规则。",
  allow: "放行整条流，后续数据会绕过规则判定。",
  block: "阻断整条流，适合明确需要中断的匹配。",
  drop: "仅丢当前包，主要对 UDP 更有意义。",
  modify: "修改当前 UDP 包；当前仅 dns modifier 生效。",
};

const POLICY_FIELD_HELP = {
  bundle_version: "策略包版本号。改成新值可另存为新版本。",
  agent_version: "目标 Agent 版本，不填则表示通用。",
  io_queue_size: "NFQUEUE 队列长度。0 表示使用默认值。",
  worker_count: "工作协程数量。0 或更小表示自动按 CPU 推断。",
  rcv_buf: "Netlink 接收缓冲区大小。0 表示系统默认。",
  snd_buf: "Netlink 发送缓冲区大小。0 表示系统默认。",
  worker_queue: "每个 worker 的内部队列长度。",
  udp_max_streams: "UDP 最大并发流缓存数量。",
  tcp_total_pages: "TCP 全局缓冲页上限。",
  tcp_pages_per_conn: "单 TCP 连接缓冲页上限。",
  io_local: "启用 INPUT/OUTPUT 模式；关闭则走 FORWARD。",
  io_rst: "阻断 TCP 时返回 RST。本地模式下通常不建议启用。",
  runtime_extra: "额外运行时键值，将原样写入 runtime.extra。",
  telemetry_analyzers: "强制启用的分析器列表。即使规则未直接引用，也会被遥测加载。",
  telemetry_rule_hit: "上报规则命中事件。",
  telemetry_suspicious_only: "仅上报可疑流量相关事件。",
  telemetry_flow_summary: "上报流摘要统计。",
  telemetry_sampling: "良性流量采样率，范围 0 到 1。",
  rule_name: "规则名称，建议稳定且可读，便于日志和审计。",
  rule_action: "规则命中后的处理动作；留空表示仅记录日志。",
  rule_log: "命中时写 ruleset 日志。",
  rule_modifier: "仅 action=modify 时生效；当前内置 dns。",
  rule_expr: "expr 表达式，按顺序匹配。第一条带 action 的命中规则会返回结果。",
  rule_modifier_args: "Modifier 参数 JSON。dns 支持 a / aaaa。",
  rule_modifier_dns_a: "DNS A 记录改写目标 IPv4。",
  rule_modifier_dns_aaaa: "DNS AAAA 记录改写目标 IPv6。",
  metadata: "策略包级元数据，可用于标记来源、批次、用途。",
  preview: "根据当前草稿实时生成的最终 payload。",
  validation: "保存前的结构化检查结果。",
};

const RULE_WIZARD_SCENARIOS = [
  { value: "tls_sni", label: "TLS SNI", description: "按 SNI 域名匹配 TLS 流量" },
  { value: "http_host", label: "HTTP Host", description: "按 Host Header 匹配 HTTP 请求" },
  { value: "dns_qname", label: "DNS 问题名", description: "按 DNS 查询域名匹配，可直接改写应答" },
  { value: "geosite_sni", label: "GeoSite", description: "按 geosite 集合批量匹配域名" },
  { value: "cidr_ip", label: "CIDR", description: "按源/目的地址段匹配内网或业务网段" },
  { value: "fet_proxy", label: "FET", description: "阻断疑似全加密代理流量" },
];

const ChartPanel = {
  name: "ChartPanel",
  props: {
    option: {
      type: Object,
      default: null,
    },
    empty: {
      type: Boolean,
      default: false,
    },
    emptyText: {
      type: String,
      default: "暂无数据",
    },
    height: {
      type: Number,
      default: 280,
    },
  },
  template: `
    <div class="chart-root" :style="{ height: height + 'px' }">
      <div ref="canvas" class="chart-canvas"></div>
      <div v-if="empty" class="chart-empty">{{ emptyText }}</div>
    </div>
  `,
  data() {
    return {
      chart: null,
      rendered: false,
      lastWidth: 0,
      lastHeight: 0,
      resizeObserver: null,
      resizeHandler: null,
      rafId: 0,
    };
  },
  methods: {
    hasContainerSize() {
      return Boolean(this.$el && this.$el.clientWidth > 0 && this.$el.clientHeight > 0);
    },

    ensureChart() {
      if (!this.$refs.canvas || !this.hasContainerSize()) {
        return false;
      }
      if (!this.chart) {
        this.chart = echarts.init(this.$refs.canvas);
      }
      return true;
    },

    syncChartSize() {
      if (!this.chart || !this.$el) {
        return false;
      }
      const width = this.$el.clientWidth || 0;
      const height = this.$el.clientHeight || 0;
      if (width === 0 || height === 0) {
        return false;
      }
      if (width !== this.lastWidth || height !== this.lastHeight) {
        this.chart.resize({ width, height });
        this.lastWidth = width;
        this.lastHeight = height;
      }
      return true;
    },

    scheduleRender() {
      if (this.rafId) {
        window.cancelAnimationFrame(this.rafId);
      }
      this.rafId = window.requestAnimationFrame(() => {
        this.rafId = 0;
        this.renderChart();
      });
    },

    renderChart() {
      if (this.empty || !this.option) {
        if (this.chart) {
          this.chart.clear();
        }
        this.rendered = false;
        this.lastWidth = this.$el?.clientWidth || 0;
        this.lastHeight = this.$el?.clientHeight || 0;
        return;
      }
      if (!this.ensureChart() || !this.syncChartSize()) {
        this.rendered = false;
        return;
      }
      try {
        this.chart.setOption(this.option, true);
        this.rendered = true;
      } catch (error) {
        this.rendered = false;
        console.error("chart render failed", error);
      }
    },

    handleResize() {
      this.scheduleRender();
    },
  },
  mounted() {
    this.$nextTick(() => {
      this.scheduleRender();
    });

    if (window.ResizeObserver) {
      this.resizeObserver = new ResizeObserver(() => this.handleResize());
      this.resizeObserver.observe(this.$el);
      return;
    }

    this.resizeHandler = () => this.handleResize();
    window.addEventListener("resize", this.resizeHandler);
  },
  watch: {
    option: {
      deep: true,
      handler() {
        this.scheduleRender();
      },
    },
    empty() {
      this.scheduleRender();
    },
    height() {
      this.scheduleRender();
    },
  },
  beforeUnmount() {
    if (this.rafId) {
      window.cancelAnimationFrame(this.rafId);
    }
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
    if (this.resizeHandler) {
      window.removeEventListener("resize", this.resizeHandler);
    }
    if (this.chart) {
      this.chart.dispose();
      this.rendered = false;
      this.chart = null;
    }
  },
};

function defaultAuth() {
  return {
    authenticated: false,
    setupRequired: false,
    user: null,
  };
}

function defaultBundleTemplate() {
  return {
    version: "",
    agentVersion: "",
    readonly: false,
    runtime: {
      io: {
        queueSize: 0,
        rcvBuf: 0,
        sndBuf: 0,
        local: false,
        rst: false,
      },
      workers: {
        count: 0,
        queueSize: 0,
        tcpMaxBufferedPagesTotal: 0,
        tcpMaxBufferedPagesPerConn: 0,
        udpMaxStreams: 0,
      },
      extra: {},
    },
    telemetry: {
      analyzers: [],
      events: {
        ruleHit: true,
        suspiciousOnly: false,
        flowSummary: false,
      },
      sampling: {
        benignFlow: 0,
      },
    },
    rules: [],
    metadata: {},
  };
}

function defaultReleaseForm() {
  return {
    version: "",
    downloadUrl: "",
    checksum: "",
    notes: "",
  };
}

function defaultAgentBuildForm() {
  return {
    targets: ["linux-amd64", "linux-arm64"],
    force: true,
    releaseVersion: "",
    releaseNotes: "",
  };
}

function defaultNodeInstallForm() {
  return {
    name: "",
    labelsText: "",
  };
}

function requestJSON(path, options = {}, expectJSON = true) {
  const sessionToken = loadSessionToken();
  return fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      ...(sessionToken ? { "X-OpenGFW-Session": sessionToken } : {}),
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    ...options,
  }).then(async (response) => {
    if (!response.ok) {
      let message = `${response.status} ${response.statusText}`;
      try {
        const data = await response.json();
        if (data && data.error) {
          message = data.error;
        }
      } catch (_) {
        // ignore
      }
      const error = new Error(message);
      error.status = response.status;
      throw error;
    }

    if (!expectJSON || response.status === 204) {
      return null;
    }
    return response.json();
  });
}

function formatTime(value, includeYear = false) {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "—";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    ...(includeYear ? { year: "numeric" } : {}),
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}

function formatClock(value) {
  return formatTime(value, true);
}

function formatChartTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

function formatNumber(value) {
  const numeric = Number(value || 0);
  return new Intl.NumberFormat("zh-CN").format(Number.isFinite(numeric) ? numeric : 0);
}

function formatLabels(labels) {
  if (!labels || !Object.keys(labels).length) {
    return "无标签";
  }
  return Object.entries(labels)
    .map(([key, value]) => `${key}=${value}`)
    .join(" / ");
}

function truncate(value, max) {
  if (!value || value.length <= max) {
    return value;
  }
  return `${value.slice(0, Math.max(0, max - 3))}...`;
}

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

function loadSessionToken() {
  if (runtimeSessionToken) {
    return runtimeSessionToken;
  }
  try {
    runtimeSessionToken = window.localStorage.getItem(SESSION_TOKEN_KEY) || "";
    return runtimeSessionToken;
  } catch (_) {
    return "";
  }
}

function saveSessionToken(token) {
  runtimeSessionToken = token || "";
  try {
    if (token) {
      window.localStorage.setItem(SESSION_TOKEN_KEY, token);
      return;
    }
    window.localStorage.removeItem(SESSION_TOKEN_KEY);
  } catch (_) {
    // ignore
  }
}

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function translateStatus(status) {
  const map = {
    online: "在线",
    pending: "待安装",
    offline: "离线",
    error: "异常",
    success: "成功",
    failed: "失败",
    unknown: "未知",
  };
  return map[status] || status || "未知";
}

function translateTaskType(type) {
  const map = {
    apply_bundle: "下发策略包",
    upgrade_agent: "升级 Agent",
  };
  return map[type] || type || "未知任务";
}

function translateEventType(type) {
  const map = {
    rule_hit: "规则命中",
    stream_action: "流动作",
    suspicious_flow: "可疑流量",
    analyzer_error: "分析器错误",
    modify_error: "修改错误",
    ruleset_match_error: "规则匹配错误",
  };
  return map[type] || type || "未知类型";
}

function translateAction(action) {
  const map = {
    allow: "放行",
    block: "阻断",
    drop: "丢弃",
    modify: "修改",
    maybe: "待定",
  };
  return map[action] || action || "—";
}

function statusTone(status) {
  const map = {
    online: "success",
    success: "success",
    pending: "warning",
    offline: "info",
    error: "danger",
    failed: "danger",
  };
  return map[status] || "info";
}

function axisTextStyle() {
  return {
    color: CHART_COLORS.slate,
    fontFamily: "Noto Sans SC",
    fontSize: 12,
  };
}

function buildTrafficTrendOption(buckets) {
  if (!buckets.length) {
    return null;
  }

  return {
    color: [CHART_COLORS.primary, CHART_COLORS.secondary, CHART_COLORS.danger],
    animationDuration: 400,
    grid: {
      top: 44,
      right: 12,
      bottom: 10,
      left: 8,
      containLabel: true,
    },
    legend: {
      top: 0,
      icon: "circle",
      itemWidth: 10,
      itemHeight: 10,
      textStyle: axisTextStyle(),
    },
    tooltip: {
      trigger: "axis",
      backgroundColor: "rgba(255,255,255,0.96)",
      borderColor: CHART_COLORS.grid,
      textStyle: {
        color: "#0f172a",
      },
    },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: buckets.map((bucket) => formatChartTime(bucket.timestamp)),
      axisLine: {
        lineStyle: {
          color: CHART_COLORS.grid,
        },
      },
      axisLabel: {
        ...axisTextStyle(),
        hideOverlap: true,
      },
      axisTick: {
        show: false,
      },
    },
    yAxis: {
      type: "value",
      splitLine: {
        lineStyle: {
          color: CHART_COLORS.grid,
        },
      },
      axisLabel: axisTextStyle(),
    },
    series: [
      {
        name: "事件总量",
        type: "line",
        smooth: true,
        showSymbol: false,
        areaStyle: {
          color: CHART_COLORS.fill,
        },
        lineStyle: {
          width: 3,
        },
        data: buckets.map((bucket) => bucket.events || 0),
      },
      {
        name: "规则命中",
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: {
          width: 2,
        },
        data: buckets.map((bucket) => bucket.ruleHits || 0),
      },
      {
        name: "可疑流量",
        type: "line",
        smooth: true,
        showSymbol: false,
        lineStyle: {
          width: 2,
          type: "dashed",
        },
        data: buckets.map((bucket) => bucket.suspicious || 0),
      },
    ],
  };
}

function buildEventTypeOption(entries) {
  if (!entries.length) {
    return null;
  }

  const total = entries.reduce((sum, [, value]) => sum + Number(value || 0), 0);

  return {
    color: [CHART_COLORS.primary, CHART_COLORS.secondary, CHART_COLORS.warning, CHART_COLORS.success, CHART_COLORS.danger],
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(255,255,255,0.96)",
      borderColor: CHART_COLORS.grid,
      textStyle: {
        color: "#0f172a",
      },
    },
    legend: {
      bottom: 0,
      left: "center",
      itemWidth: 10,
      itemHeight: 10,
      textStyle: axisTextStyle(),
    },
    graphic: [
      {
        type: "text",
        left: "center",
        top: "39%",
        style: {
          text: `${formatNumber(total)}\n事件`,
          textAlign: "center",
          fill: "#0f172a",
          font: "600 20px 'Noto Sans SC'",
          lineHeight: 28,
        },
      },
    ],
    series: [
      {
        type: "pie",
        radius: ["56%", "76%"],
        center: ["50%", "42%"],
        avoidLabelOverlap: true,
        itemStyle: {
          borderColor: "#ffffff",
          borderWidth: 2,
        },
        label: {
          formatter: ({ name, percent }) => `${name}\n${percent}%`,
          color: CHART_COLORS.slate,
          fontSize: 12,
        },
        labelLine: {
          length: 12,
          length2: 10,
          lineStyle: {
            color: CHART_COLORS.grid,
          },
        },
        data: entries.map(([key, value]) => ({
          name: translateEventType(key),
          value: Number(value || 0),
        })),
      },
    ],
  };
}

function buildHorizontalBarOption(items, getLabel, getValue, getColor = () => CHART_COLORS.primary) {
  const rows = items
    .map((item) => ({
      rawLabel: getLabel(item),
      label: truncate(getLabel(item), 14),
      value: Number(getValue(item) || 0),
      color: getColor(item),
    }))
    .filter((item) => item.value > 0)
    .slice(0, 8)
    .reverse();

  if (!rows.length) {
    return null;
  }

  return {
    animationDuration: 350,
    grid: {
      top: 8,
      right: 12,
      bottom: 4,
      left: 8,
      containLabel: true,
    },
    tooltip: {
      trigger: "axis",
      axisPointer: {
        type: "shadow",
      },
      backgroundColor: "rgba(255,255,255,0.96)",
      borderColor: CHART_COLORS.grid,
      textStyle: {
        color: "#0f172a",
      },
      formatter(params) {
        const row = rows[params[0].dataIndex];
        return `${row.rawLabel}<br />${formatNumber(row.value)}`;
      },
    },
    xAxis: {
      type: "value",
      splitLine: {
        lineStyle: {
          color: CHART_COLORS.grid,
        },
      },
      axisLabel: axisTextStyle(),
      axisTick: {
        show: false,
      },
    },
    yAxis: {
      type: "category",
      data: rows.map((row) => row.label),
      axisLabel: {
        ...axisTextStyle(),
        width: 104,
        overflow: "truncate",
      },
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
    },
    series: [
      {
        type: "bar",
        barWidth: 12,
        data: rows.map((row) => ({
          value: row.value,
          itemStyle: {
            color: row.color,
            borderRadius: [0, 8, 8, 0],
          },
        })),
      },
    ],
  };
}

function buildHealthGaugeOption(onlineRate, suspiciousRate) {
  return {
    animationDuration: 350,
    series: [
      {
        type: "gauge",
        min: 0,
        max: 100,
        startAngle: 210,
        endAngle: -30,
        center: ["50%", "56%"],
        progress: {
          show: true,
          width: 12,
          itemStyle: {
            color: onlineRate >= 90 ? CHART_COLORS.success : onlineRate >= 60 ? CHART_COLORS.warning : CHART_COLORS.danger,
          },
        },
        axisLine: {
          lineStyle: {
            width: 12,
            color: [[1, "rgba(148, 163, 184, 0.16)"]],
          },
        },
        splitLine: { show: false },
        axisTick: { show: false },
        axisLabel: { show: false },
        pointer: { show: false },
        anchor: { show: false },
        title: {
          offsetCenter: [0, "52%"],
          color: CHART_COLORS.slate,
          fontSize: 12,
        },
        detail: {
          valueAnimation: true,
          formatter: "{value}%",
          offsetCenter: [0, "16%"],
          color: "#0f172a",
          fontSize: 28,
          fontWeight: 600,
        },
        data: [
          {
            value: onlineRate,
            name: `风险占比 ${suspiciousRate}%`,
          },
        ],
      },
    ],
  };
}

function buildHealthStatusOption(onlineRate, suspiciousRate) {
  return {
    animationDuration: 300,
    grid: {
      top: 12,
      right: 12,
      bottom: 4,
      left: 8,
      containLabel: true,
    },
    xAxis: {
      type: "value",
      min: 0,
      max: 100,
      splitLine: {
        lineStyle: {
          color: CHART_COLORS.grid,
        },
      },
      axisLabel: {
        ...axisTextStyle(),
        formatter: "{value}%",
      },
    },
    yAxis: {
      type: "category",
      data: ["在线率", "风险占比"],
      axisLabel: axisTextStyle(),
      axisLine: {
        show: false,
      },
      axisTick: {
        show: false,
      },
    },
    series: [
      {
        type: "bar",
        barWidth: 16,
        data: [
          {
            value: onlineRate,
            itemStyle: {
              color: onlineRate >= 90 ? CHART_COLORS.success : onlineRate >= 60 ? CHART_COLORS.warning : CHART_COLORS.danger,
              borderRadius: [0, 8, 8, 0],
            },
          },
          {
            value: suspiciousRate,
            itemStyle: {
              color: CHART_COLORS.danger,
              borderRadius: [0, 8, 8, 0],
            },
          },
        ],
        label: {
          show: true,
          position: "right",
          formatter: "{c}%",
          color: "#0f172a",
          fontSize: 12,
        },
      },
    ],
  };
}

createApp({
  components: {
    ChartPanel,
  },
  data() {
    return {
      booting: true,
      auth: defaultAuth(),
      authError: "",
      authSubmitting: false,
      setupForm: {
        username: "",
        password: "",
        confirmPassword: "",
      },
      loginForm: {
        username: "",
        password: "",
      },
      passwordForm: {
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      },
      accountDialogVisible: false,
      accountError: "",
      accountSuccess: "",
      passwordSubmitting: false,
      activeView: "overview",
      detailRoute: {
        type: "",
        id: "",
      },
      routeChangeHandler: null,
      statusState: "idle",
      statusText: "等待认证",
      lastSyncAt: null,
      clockNow: new Date(),
      clockTimer: null,
      visibilityChangeHandler: null,
      overviewRefreshTimer: null,
      overviewRefreshIntervalMs: 3000,
      overviewLiveRefreshing: false,
      isRefreshing: false,
      loading: {
        overview: false,
        nodes: false,
        bundles: false,
        releases: false,
        eventsView: false,
      },
      nodeInstallDialogVisible: false,
      nodeInstallForm: defaultNodeInstallForm(),
      nodeInstallSubmitting: false,
      nodeInstallError: "",
      nodeInstallSuccess: "",
      nodeCommandDialogVisible: false,
      nodeCommandTarget: null,
      nodeCommandSubmitting: false,
      nodeCommandError: "",
      nodeCommandResult: null,
      agentBuildDialogVisible: false,
      agentBuildForm: defaultAgentBuildForm(),
      agentBuildSubmitting: false,
      agentBuildError: "",
      agentBuildSuccess: "",
      agentBuildResults: [],
      releaseDialogVisible: false,
      releaseForm: defaultReleaseForm(),
      releaseSubmitting: false,
      releaseError: "",
      releaseSuccess: "",
      filters: {
        nodes: {
          status: "",
          label: "",
          search: "",
        },
        bundles: {
          search: "",
        },
        releases: {
          search: "",
        },
        eventsView: {
          agentId: "",
          search: "",
          type: "",
          proto: "",
          ruleName: "",
          action: "",
          srcIp: "",
          dstIp: "",
          port: "",
          minSuspicion: 0,
          since: "",
          until: "",
        },
      },
      summary: {
        nodes: 0,
        onlineNodes: 0,
        eventCount: 0,
        suspiciousEvents: 0,
        eventsByType: {},
        eventsByProtocol: {},
      },
      suspiciousEvents: [],
      rules: [],
      protocols: [],
      trafficSeries: [],
      nodes: [],
      selectedNode: null,
      selectedNodeTasks: [],
      selectedNodeEvents: [],
      selectedNodeReport: null,
      selectedNodeTrafficSeries: [],
      eventDetailDialogVisible: false,
      eventDetailEvent: null,
      eventRows: [],
      eventRowsTotal: 0,
      eventRowsPage: 1,
      eventRowsPageSize: 20,
      bundles: [],
      selectedBundle: null,
      bundleDraft: null,
      bundleSaveError: "",
      bundleSaveSuccess: "",
      bundleSaving: false,
      rolloutNodes: [],
      bundleRolloutTargetIds: [],
      bundleRolloutSubmitting: false,
      bundleRolloutError: "",
      bundleRolloutSuccess: "",
      bundleNodeOperationState: {},
      releaseRolloutTargetIds: [],
      releaseRolloutSubmitting: false,
      releaseRolloutError: "",
      releaseRolloutSuccess: "",
      bundleDetachSubmittingId: "",
      ruleWizardScenarios: RULE_WIZARD_SCENARIOS,
      ruleWizardStep: 0,
      ruleWizard: {
        scenario: "tls_sni",
        name: "",
        action: "block",
        log: false,
        domain: "",
        geosite: "category-ads-all",
        cidr: "",
        cidrSide: "either",
        rewriteIPv4: "127.0.0.1",
        rewriteIPv6: "::1",
      },
      ruleTemplates: RULE_TEMPLATES,
      ruleExprSnippets: RULE_EXPR_SNIPPETS,
      ruleFieldHints: RULE_FIELD_HINTS,
      releases: [],
      selectedRelease: null,
      nodeStats: [],
      availableAnalyzers: AVAILABLE_ANALYZERS,
      availableBuildTargets: AGENT_BUILD_TARGETS,
    };
  },
  computed: {
    currentViewTitle() {
      if (this.detailRoute.type === "nodes") {
        return this.selectedNode ? (this.selectedNode.name || this.selectedNode.id) : "节点详情";
      }
      if (this.detailRoute.type === "policies") {
        if (this.detailRoute.id === "__new__") {
          return "新建策略包";
        }
        return this.selectedBundle?.version || "策略详情";
      }
      if (this.detailRoute.type === "releases") {
        return this.selectedRelease?.version || "发布详情";
      }
      return VIEW_META[this.activeView]?.title || "主控台";
    },
    isNodeDetailPage() {
      return this.detailRoute.type === "nodes";
    },
    isPolicyDetailPage() {
      return this.detailRoute.type === "policies";
    },
    isReleaseDetailPage() {
      return this.detailRoute.type === "releases";
    },
    isNewBundleDraft() {
      return this.detailRoute.type === "policies" && this.detailRoute.id === "__new__";
    },
    selectedNodeUsingDefaultBundle() {
      return String(this.selectedNode?.bundleVersion || "").trim() === DEFAULT_REPORTING_BUNDLE_VERSION;
    },
    selectedBundleReadonly() {
      return Boolean(this.bundleDraft?.readonly || this.selectedBundle?.readonly);
    },
    onlineRate() {
      if (!this.summary.nodes) {
        return 0;
      }
      return Math.round((Number(this.summary.onlineNodes || 0) / Number(this.summary.nodes || 1)) * 100);
    },
    suspiciousRate() {
      if (!this.summary.eventCount) {
        return 0;
      }
      return Math.round((Number(this.summary.suspiciousEvents || 0) / Number(this.summary.eventCount || 1)) * 100);
    },
    protocolCount() {
      return Object.keys(this.summary.eventsByProtocol || {}).length;
    },
    lastSyncLabel() {
      return this.lastSyncAt ? formatTime(this.lastSyncAt, true) : "尚未同步";
    },
    clockLabel() {
      return formatClock(this.clockNow);
    },
    statusTagType() {
      const map = {
        idle: "info",
        syncing: "warning",
        success: "success",
        degraded: "danger",
      };
      return map[this.statusState] || "info";
    },
    overviewCards() {
      return [
        {
          label: "在线节点",
          value: formatNumber(this.summary.onlineNodes),
          subtle: `共 ${formatNumber(this.summary.nodes)} 个节点`,
        },
        {
          label: "事件总量",
          value: formatNumber(this.summary.eventCount),
          subtle: `${formatNumber(this.summary.suspiciousEvents)} 条可疑流量`,
        },
        {
          label: "可疑流量",
          value: formatNumber(this.summary.suspiciousEvents),
          subtle: `风险占比 ${this.suspiciousRate}%`,
        },
        {
          label: "活跃协议",
          value: formatNumber(this.protocolCount),
          subtle: `${formatNumber(this.rules.length)} 条高频规则`,
        },
      ];
    },
    overviewFocusItems() {
      const topProtocol = this.protocols[0] || null;
      const topRule = this.rules[0] || null;
      return [
        {
          label: "控制面状态",
          value: this.statusText,
          subtle: this.lastSyncAt ? `最近同步 ${this.lastSyncLabel}` : "等待首次同步",
        },
        {
          label: "高频协议",
          value: topProtocol?.protocol || "—",
          subtle: topProtocol ? `${formatNumber(topProtocol.events || 0)} 条事件` : "暂无协议热度",
        },
        {
          label: "重点规则",
          value: topRule?.ruleName || "—",
          subtle: topRule ? `${formatNumber(topRule.hits || 0)} 次命中` : "暂无规则命中",
        },
      ];
    },
    eventTypeEntries() {
      return Object.entries(this.summary.eventsByType || {}).filter(([, value]) => Number(value || 0) > 0);
    },
    trafficTrendOption() {
      return buildTrafficTrendOption(this.trafficSeries);
    },
    eventTypeOption() {
      return buildEventTypeOption(this.eventTypeEntries);
    },
    ruleHitsOption() {
      return buildHorizontalBarOption(this.rules, (item) => item.ruleName || "unknown", (item) => item.hits || 0, () => CHART_COLORS.primary);
    },
    protocolOption() {
      return buildHorizontalBarOption(
        this.protocols,
        (item) => item.protocol || "unknown",
        (item) => item.events || 0,
        (item) => (Number(item.suspiciousEvents || 0) > 0 ? CHART_COLORS.warning : CHART_COLORS.secondary)
      );
    },
    nodeVolumeOption() {
      return buildHorizontalBarOption(
        this.nodeStats,
        (item) => item.agentId || "node",
        (item) => item.events || 0,
        (item) => (Number(item.suspiciousEvents || 0) > 0 ? CHART_COLORS.danger : CHART_COLORS.primary)
      );
    },
    healthStatusOption() {
      if (!this.summary.nodes && !this.summary.eventCount) {
        return null;
      }
      return buildHealthStatusOption(this.onlineRate, this.suspiciousRate);
    },
    nodeOverviewCards() {
      const total = this.nodes.length;
      const byStatus = this.nodes.reduce((acc, node) => {
        const status = node.status || "unknown";
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {});
      const hasFilter = this.filters.nodes.status || this.filters.nodes.label || this.filters.nodes.search;
      return [
        {
          label: "节点总数",
          value: formatNumber(total),
          subtle: hasFilter ? "当前筛选结果" : "当前资产视图",
        },
        {
          label: "在线",
          value: formatNumber(byStatus.online || 0),
          subtle: total ? `${Math.round(((byStatus.online || 0) / total) * 100)}%` : "0%",
        },
        {
          label: "待安装",
          value: formatNumber(byStatus.pending || 0),
          subtle: "等待接入",
        },
        {
          label: "离线 / 异常",
          value: formatNumber((byStatus.offline || 0) + (byStatus.error || 0)),
          subtle: `${formatNumber(byStatus.error || 0)} 异常`,
        },
      ];
    },
    policyOverviewCards() {
      const editableBundles = this.bundles.filter((bundle) => !bundle.readonly);
      const totalBundles = editableBundles.length;
      const totalRules = editableBundles.reduce((sum, bundle) => sum + ((bundle.rules || []).length || 0), 0);
      const analyzerSet = new Set(
        editableBundles.flatMap((bundle) => ((bundle.telemetry || {}).analyzers || []))
      );
      const latestBundle = editableBundles[editableBundles.length - 1] || null;
      return [
        {
          label: "策略包",
          value: formatNumber(totalBundles),
          subtle: "当前版本池",
        },
        {
          label: "规则总数",
          value: formatNumber(totalRules),
          subtle: totalBundles ? `平均 ${formatNumber(Math.round(totalRules / Math.max(totalBundles, 1)))} 条` : "0",
        },
        {
          label: "分析器覆盖",
          value: formatNumber(analyzerSet.size),
          subtle: "已启用分析器",
        },
        {
          label: "最新版本",
          value: latestBundle?.version || "—",
          subtle: latestBundle?.createdAt ? formatTime(latestBundle.createdAt) : "暂无发布",
        },
      ];
    },
    releaseOverviewCards() {
      const withChecksum = this.releases.filter((item) => item.checksum).length;
      const withNotes = this.releases.filter((item) => item.notes).length;
      const latestRelease = this.releases[this.releases.length - 1] || null;
      return [
        {
          label: "发布包",
          value: formatNumber(this.releases.length),
          subtle: "版本仓库",
        },
        {
          label: "校验覆盖",
          value: formatNumber(withChecksum),
          subtle: this.releases.length ? `${Math.round((withChecksum / this.releases.length) * 100)}%` : "0%",
        },
        {
          label: "带备注版本",
          value: formatNumber(withNotes),
          subtle: "可追溯说明",
        },
        {
          label: "最新版本",
          value: latestRelease?.version || "—",
          subtle: latestRelease?.createdAt ? formatTime(latestRelease.createdAt) : "暂无记录",
        },
      ];
    },
    selectedNodeHighlights() {
      if (!this.selectedNode) {
        return [];
      }
      return [
        { label: "管理 IP", value: this.selectedNode.managementIp || "—", mono: true },
        { label: "Agent", value: this.selectedNode.agentVersion || "—", mono: true },
        { label: "策略包", value: this.selectedNode.bundleVersion || "—", mono: true },
        { label: "最近心跳", value: formatTime(this.selectedNode.lastSeenAt), mono: true },
        { label: "事件数", value: formatNumber(this.selectedNodeReport?.events || this.selectedNodeEvents.length), mono: true },
        { label: "命中规则", value: formatNumber(this.selectedNodeReport?.ruleHits || 0), mono: true },
      ];
    },
    selectedNodeLabelTags() {
      return this.selectedNode?.labels || [];
    },
    selectedNodeCapabilityTags() {
      return this.selectedNode?.capabilities || [];
    },
    selectedNodeMetadataEntries() {
      if (!this.selectedNode?.metadata) {
        return [];
      }
      return Object.entries(this.selectedNode.metadata).map(([key, value]) => ({
        key,
        value: String(value),
      }));
    },
    selectedNodeDetails() {
      if (!this.selectedNode) {
        return [];
      }
      return [
        { label: "ID", value: this.selectedNode.id || "—", mono: true },
        { label: "名称", value: this.selectedNode.name || "—", mono: false },
        { label: "主机名", value: this.selectedNode.hostname || "—", mono: false },
        { label: "平台", value: this.nodePlatformLabel(this.selectedNode) || "—", mono: true },
        { label: "标签数", value: formatNumber((this.selectedNode.labels || []).length), mono: true },
        { label: "能力数", value: formatNumber((this.selectedNode.capabilities || []).length), mono: true },
        { label: "元数据项", value: formatNumber(Object.keys(this.selectedNode.metadata || {}).length), mono: true },
      ];
    },
    selectedNodeTrafficOption() {
      return buildTrafficTrendOption(this.selectedNodeTrafficSeries);
    },
    eventDetailPropsText() {
      if (!this.eventDetailEvent?.props) {
        return "—";
      }
      return prettyJson(this.eventDetailEvent.props);
    },
    selectedBundleHighlights() {
      const source = this.bundleDraft || this.selectedBundle;
      if (!source) {
        return [];
      }
      return [
        { label: "类型", value: source.readonly ? "系统默认上报策略" : "自定义策略包", mono: false },
        { label: "版本", value: source.version || "—", mono: true },
        { label: "Agent", value: source.agentVersion || "—", mono: true },
        { label: "规则数", value: formatNumber((source.rules || []).length), mono: true },
        {
          label: "分析器",
          value: formatNumber((((source.telemetry || {}).analyzers) || []).length),
          mono: true,
        },
      ];
    },
    bundleDraftPreview() {
      if (!this.bundleDraft) {
        return "";
      }
      try {
        return prettyJson(this.buildBundlePayload());
      } catch (_) {
        return "";
      }
    },
    bundleDraftValidationIssues() {
      if (!this.bundleDraft) {
        return [];
      }
      if (this.bundleDraft.readonly) {
        return [];
      }

      const issues = [];
      if (!String(this.bundleDraft.version || "").trim()) {
        issues.push("策略版本不能为空。");
      }
      if (!this.bundleDraft.rules.length) {
        issues.push("至少需要一条规则。");
      }

      const ruleNames = new Set();
      this.bundleDraft.rules.forEach((rule, index) => {
        const name = String(rule.name || "").trim();
        if (!name) {
          issues.push(`第 ${index + 1} 条规则缺少名称。`);
        } else if (ruleNames.has(name)) {
          issues.push(`规则名称重复：${name}`);
        } else {
          ruleNames.add(name);
        }
        issues.push(...this.getRuleValidationIssues(rule, index).filter((item) => !item.includes("缺少名称。")));
      });

      if (Number(this.bundleDraft.telemetry.sampling.benignFlow) < 0 || Number(this.bundleDraft.telemetry.sampling.benignFlow) > 1) {
        issues.push("Benign Flow Sampling 必须在 0 到 1 之间。");
      }

      const metadataKeys = new Set();
      (this.bundleDraft.metadataRows || []).forEach((row, index) => {
        const key = String(row.key || "").trim();
        if (!key) {
          return;
        }
        if (metadataKeys.has(key)) {
          issues.push(`元数据键重复：${key}（第 ${index + 1} 行）`);
        } else {
          metadataKeys.add(key);
        }
      });

      return issues;
    },
    selectedReleaseHighlights() {
      if (!this.selectedRelease) {
        return [];
      }
      return [
        { label: "版本", value: this.selectedRelease.version || "—", mono: true },
        { label: "创建时间", value: formatTime(this.selectedRelease.createdAt), mono: true },
        { label: "资产数", value: formatNumber((this.selectedRelease.assets || []).length || (this.selectedRelease.downloadUrl ? 1 : 0)), mono: true },
        { label: "备注", value: this.selectedRelease.notes ? "已填写" : "未填写", mono: false },
      ];
    },
    selectedReleaseAssetTargets() {
      return new Set((this.selectedRelease?.assets || []).map((asset) => `${asset.goos}/${asset.goarch}`));
    },
    rolloutNodeOptions() {
      return this.rolloutNodes.map((node) => ({
        value: node.id,
        label: node.name || node.id,
        status: translateStatus(node.status),
        meta: [
          node.agentVersion ? `当前 ${node.agentVersion}` : "当前版本未知",
          this.nodePlatformLabel(node),
          node.hostname,
          node.managementIp,
        ].filter(Boolean).join(" / "),
      }));
    },
    rolloutOnlineNodeIds() {
      return this.rolloutNodes.filter((node) => node.status === "online").map((node) => node.id);
    },
    selectedRolloutNodes() {
      return this.rolloutNodes.filter((node) => this.bundleRolloutTargetIds.includes(node.id));
    },
    currentBundleAssignedNodes() {
      const version = String(this.selectedBundle?.version || "").trim();
      if (!version) {
        return [];
      }
      return this.rolloutNodes
        .filter((node) => String(node.bundleVersion || "").trim() === version)
        .sort((a, b) => String(a.name || a.id).localeCompare(String(b.name || b.id), "zh-CN"));
    },
    rolloutSummaryCards() {
      const total = this.rolloutNodes.length;
      const online = this.rolloutOnlineNodeIds.length;
      return [
        { label: "节点总数", value: formatNumber(total), subtle: "可下发目标" },
        { label: "在线节点", value: formatNumber(online), subtle: total ? `${Math.round((online / total) * 100)}%` : "0%" },
        { label: "已关联", value: formatNumber(this.currentBundleAssignedNodes.length), subtle: "当前使用该策略" },
        { label: "已选择", value: formatNumber(this.bundleRolloutTargetIds.length), subtle: "当前下发范围" },
      ];
    },
    selectedReleaseRolloutNodes() {
      return this.rolloutNodes.filter((node) => this.releaseRolloutTargetIds.includes(node.id));
    },
    releaseUpgradeableNodeIds() {
      const targetVersion = String(this.selectedRelease?.version || "").trim();
      if (!targetVersion) {
        return [];
      }
      return this.rolloutNodes
        .filter((node) => {
          if (node.status !== "online" || String(node.agentVersion || "").trim() === targetVersion) {
            return false;
          }
          if (!this.selectedReleaseAssetTargets.size) {
            return true;
          }
          const platform = this.nodePlatformKey(node);
          return platform ? this.selectedReleaseAssetTargets.has(platform) : false;
        })
        .map((node) => node.id);
    },
    releaseRolloutSummaryCards() {
      const total = this.rolloutNodes.length;
      const online = this.rolloutOnlineNodeIds.length;
      return [
        { label: "节点总数", value: formatNumber(total), subtle: "可升级目标" },
        { label: "在线节点", value: formatNumber(online), subtle: total ? `${Math.round((online / total) * 100)}%` : "0%" },
        { label: "待升级", value: formatNumber(this.releaseUpgradeableNodeIds.length), subtle: "与目标版本不同" },
        { label: "已选择", value: formatNumber(this.releaseRolloutTargetIds.length), subtle: "当前升级范围" },
      ];
    },
    ruleWizardSteps() {
      return [
        { key: "scenario", label: "场景", title: "选择规则场景" },
        { key: "match", label: "条件", title: "填写匹配条件" },
        { key: "action", label: "动作", title: "设置处理动作" },
        { key: "review", label: "预览", title: "确认并加入" },
      ];
    },
    currentRuleWizardMeta() {
      return this.ruleWizardScenarios.find((item) => item.value === this.ruleWizard.scenario) || null;
    },
    ruleWizardPreview() {
      try {
        return this.buildRuleFromWizard();
      } catch (_) {
        return null;
      }
    },
    ruleWizardIssues() {
      const issues = [];
      const name = String(this.ruleWizard.name || "").trim();
      if (!name) {
        issues.push("规则名称不能为空。");
      }
      if (this.ruleWizard.scenario === "tls_sni" && !String(this.ruleWizard.domain || "").trim()) {
        issues.push("请填写要匹配的 TLS SNI 域名。");
      }
      if (this.ruleWizard.scenario === "http_host" && !String(this.ruleWizard.domain || "").trim()) {
        issues.push("请填写要匹配的 HTTP Host。");
      }
      if (this.ruleWizard.scenario === "dns_qname" && !String(this.ruleWizard.domain || "").trim()) {
        issues.push("请填写要匹配的 DNS 域名。");
      }
      if (this.ruleWizard.scenario === "geosite_sni" && !String(this.ruleWizard.geosite || "").trim()) {
        issues.push("请填写 GeoSite 列表名。");
      }
      if (this.ruleWizard.scenario === "cidr_ip" && !String(this.ruleWizard.cidr || "").trim()) {
        issues.push("请填写 CIDR 网段。");
      }
      if (this.ruleWizard.scenario === "dns_qname" && this.ruleWizard.action === "modify") {
        const hasA = String(this.ruleWizard.rewriteIPv4 || "").trim();
        const hasAAAA = String(this.ruleWizard.rewriteIPv6 || "").trim();
        if (!hasA && !hasAAAA) {
          issues.push("DNS 改写至少填写一个 A / AAAA 目标。");
        }
        if (hasA && !this.isLikelyIPv4(hasA)) {
          issues.push("DNS 改写的 A 记录不是合法 IPv4。");
        }
        if (hasAAAA && !this.isLikelyIPv6(hasAAAA)) {
          issues.push("DNS 改写的 AAAA 记录不是合法 IPv6。");
        }
      }
      return issues;
    },
    ruleWizardStepIssues() {
      return this.getRuleWizardStepIssues(this.ruleWizardStep);
    },
    canAdvanceRuleWizardStep() {
      if (this.ruleWizardStep >= this.ruleWizardSteps.length - 1) {
        return this.ruleWizardIssues.length === 0;
      }
      return this.ruleWizardStepIssues.length === 0;
    },
  },
  watch: {
    accountDialogVisible(value) {
      if (!value) {
        this.passwordForm = {
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        };
      }
      this.resetAccountFeedback();
    },
    nodeInstallDialogVisible(value) {
      if (!value) {
        this.nodeInstallForm = defaultNodeInstallForm();
        this.nodeInstallSubmitting = false;
        this.nodeInstallError = "";
        this.nodeInstallSuccess = "";
      }
    },
    nodeCommandDialogVisible(value) {
      if (!value) {
        this.nodeCommandTarget = null;
        this.nodeCommandSubmitting = false;
        this.nodeCommandError = "";
        this.nodeCommandResult = null;
      }
    },
    agentBuildDialogVisible(value) {
      if (!value) {
        this.agentBuildForm = defaultAgentBuildForm();
        this.agentBuildSubmitting = false;
        this.agentBuildError = "";
        this.agentBuildSuccess = "";
        this.agentBuildResults = [];
      }
    },
    releaseDialogVisible(value) {
      if (!value) {
        this.releaseForm = defaultReleaseForm();
        this.releaseSubmitting = false;
        this.releaseError = "";
        this.releaseSuccess = "";
      }
    },
    selectedBundle: {
      deep: true,
      handler(bundle) {
        if (bundle) {
          this.syncBundleDraft(bundle);
          this.bundleRolloutTargetIds = [];
          this.bundleRolloutError = "";
          this.bundleRolloutSuccess = "";
          this.resetRuleWizard();
        } else {
          this.bundleDraft = null;
          this.bundleSaveError = "";
          this.bundleSaveSuccess = "";
          this.bundleRolloutTargetIds = [];
          this.bundleRolloutError = "";
          this.bundleRolloutSuccess = "";
          this.resetRuleWizard();
        }
      },
    },
    selectedRelease(release) {
      if (release) {
        this.releaseRolloutTargetIds = [];
        this.releaseRolloutError = "";
        this.releaseRolloutSuccess = "";
        return;
      }
      this.releaseRolloutTargetIds = [];
      this.releaseRolloutError = "";
      this.releaseRolloutSuccess = "";
    },
    activeView(view) {
      if (view === "overview") {
        this.startOverviewAutoRefresh();
        return;
      }
      this.stopOverviewAutoRefresh();
    },
    booting(value) {
      if (!value) {
        this.startOverviewAutoRefresh();
      }
    },
    "auth.authenticated"(value) {
      if (value) {
        this.startOverviewAutoRefresh();
        return;
      }
      this.stopOverviewAutoRefresh();
    },
  },
  methods: {
    formatTime,
    formatNumber,
    formatLabels,
    prettyJson,
    truncate,
    translateStatus,
    translateTaskType,
    translateEventType,
    translateAction,
    statusTone,

    isReadonlyBundle(bundle) {
      return Boolean(bundle?.readonly);
    },

    bundleDisplayName(bundle) {
      if (this.isReadonlyBundle(bundle)) {
        return "系统默认上报策略";
      }
      return bundle?.version || "—";
    },

    bundleTelemetrySummaryRows(bundle) {
      const source = bundle || this.bundleDraft || this.selectedBundle;
      const profile = source?.telemetry || {};
      const events = profile.events || {};
      return [
        {
          label: "分析器",
          value: (profile.analyzers || []).length ? profile.analyzers.join(", ") : "默认分析器全集",
          mono: false,
        },
        {
          label: "Rule Hit",
          value: events.ruleHit ? "开启" : "关闭",
          mono: false,
        },
        {
          label: "Flow Summary",
          value: events.flowSummary ? "开启" : "关闭",
          mono: false,
        },
        {
          label: "Suspicious Only",
          value: events.suspiciousOnly ? "开启" : "关闭",
          mono: false,
        },
        {
          label: "Benign Flow Sampling",
          value: String((profile.sampling || {}).benignFlow ?? 0),
          mono: true,
        },
      ];
    },

    bundleRuntimeSummaryRows(bundle) {
      const source = bundle || this.bundleDraft || this.selectedBundle;
      const runtime = source?.runtime || {};
      const io = runtime.io || {};
      const workers = runtime.workers || {};
      return [
        { label: "本地模式", value: io.local ? "开启" : "关闭", mono: false },
        { label: "Queue Size", value: String(io.queueSize || 0), mono: true },
        { label: "Recv Buffer", value: String(io.rcvBuf || 0), mono: true },
        { label: "Send Buffer", value: String(io.sndBuf || 0), mono: true },
        { label: "Workers", value: String(workers.count || 0), mono: true },
        { label: "Worker Queue", value: String(workers.queueSize || 0), mono: true },
        { label: "UDP Streams", value: String(workers.udpMaxStreams || 0), mono: true },
        { label: "TCP Total Pages", value: String(workers.tcpMaxBufferedPagesTotal || 0), mono: true },
        { label: "TCP Pages / Conn", value: String(workers.tcpMaxBufferedPagesPerConn || 0), mono: true },
      ];
    },

    setBundleNodeOperation(nodeIds, state) {
      const next = {
        ...(this.bundleNodeOperationState || {}),
      };
      (nodeIds || []).forEach((id) => {
        if (!id) {
          return;
        }
        next[id] = state;
      });
      this.bundleNodeOperationState = next;
    },

    clearBundleNodeOperation(nodeIds) {
      const next = {
        ...(this.bundleNodeOperationState || {}),
      };
      (nodeIds || []).forEach((id) => {
        delete next[id];
      });
      this.bundleNodeOperationState = next;
    },

    wait(ms) {
      return new Promise((resolve) => {
        window.setTimeout(resolve, ms);
      });
    },

    async waitForNodeBundleState(agentIds, matcher, options = {}) {
      const uniqueIds = Array.from(new Set((agentIds || []).filter(Boolean)));
      const attempts = Number(options.attempts || 8);
      const intervalMs = Number(options.intervalMs || 1500);
      let matchedIds = [];

      for (let attempt = 0; attempt < attempts; attempt += 1) {
        await this.loadRolloutNodes();
        const byId = new Map(this.rolloutNodes.map((node) => [node.id, node]));
        matchedIds = uniqueIds.filter((id) => matcher(byId.get(id) || null));
        if (matchedIds.length === uniqueIds.length) {
          break;
        }
        if (attempt < attempts - 1) {
          await this.wait(intervalMs);
        }
      }

      const matchedIdSet = new Set(matchedIds);
      return {
        complete: matchedIds.length === uniqueIds.length,
        matchedIds,
        pendingIds: uniqueIds.filter((id) => !matchedIdSet.has(id)),
      };
    },

    isUnauthorized(error) {
      return error && (error.status === 401 || String(error.message || "").toLowerCase().includes("unauthorized"));
    },

    resetAccountFeedback() {
      this.accountError = "";
      this.accountSuccess = "";
    },

    formatPasswordChangeError(error) {
      const message = String(error?.message || error || "");
      if (message === "current password is incorrect") {
        return "当前密码不正确，请重新输入。";
      }
      if (message === "new password must be different from current password") {
        return "新密码不能与当前密码相同。";
      }
      return message || "密码更新失败，请稍后再试。";
    },

    resetNodeInstallFeedback() {
      this.nodeInstallError = "";
      this.nodeInstallSuccess = "";
    },

    resetNodeCommandFeedback() {
      this.nodeCommandError = "";
    },

    resetAgentBuildFeedback() {
      this.agentBuildError = "";
      this.agentBuildSuccess = "";
    },

    resetReleaseFeedback() {
      this.releaseError = "";
      this.releaseSuccess = "";
    },

    parseLineList(value) {
      return Array.from(
        new Set(
          String(value || "")
            .split(/[\n,]/)
            .map((item) => item.trim())
            .filter(Boolean)
        )
      );
    },

    eventFlowLabel(event) {
      if (!event) {
        return "—";
      }
      return `${event.srcIp || "—"}:${event.srcPort || "—"} → ${event.dstIp || "—"}:${event.dstPort || "—"}`;
    },

    eventPropsSummary(event) {
      const props = event?.props || {};
      const parts = [];
      const tlsSni = props?.tls?.req?.sni;
      const httpHost = props?.http?.req?.headers?.host;
      const dnsQuestion = props?.dns?.questions?.[0]?.name;
      if (tlsSni) {
        parts.push(`SNI ${tlsSni}`);
      }
      if (httpHost) {
        parts.push(`Host ${httpHost}`);
      }
      if (dnsQuestion) {
        parts.push(`DNS ${dnsQuestion}`);
      }
      if (props?.fet?.yes === true) {
        parts.push("FET");
      }
      if (props?.trojan?.yes === true) {
        parts.push("Trojan");
      }
      return parts.join(" · ") || "—";
    },

    hasEventDetailValue(value) {
      if (value === null || value === undefined) {
        return false;
      }
      if (typeof value === "string") {
        return value.trim() !== "";
      }
      if (Array.isArray(value)) {
        return value.length > 0;
      }
      if (typeof value === "object") {
        return Object.keys(value).length > 0;
      }
      return true;
    },

    formatEventDetailValue(value) {
      if (value === null || value === undefined) {
        return "—";
      }
      if (typeof value === "string") {
        return value || "—";
      }
      if (typeof value === "number" || typeof value === "boolean") {
        return String(value);
      }
      if (Array.isArray(value)) {
        if (!value.length) {
          return "—";
        }
        if (value.every((item) => ["string", "number", "boolean"].includes(typeof item))) {
          return value.join(", ");
        }
      }
      return prettyJson(value);
    },

    buildEventDetailSection(title, entries) {
      const rows = entries
        .filter((entry) => this.hasEventDetailValue(entry.value))
        .map((entry) => ({
          label: entry.label,
          value: this.formatEventDetailValue(entry.value),
          mono: Boolean(entry.mono),
        }));
      if (!rows.length) {
        return null;
      }
      return { title, rows };
    },

    normalizeDateFilter(value) {
      if (!value) {
        return "";
      }
      const numeric = Number(value);
      const date = Number.isFinite(numeric) ? new Date(numeric) : new Date(value);
      if (Number.isNaN(date.getTime())) {
        return "";
      }
      return date.toISOString();
    },

    escapeCsv(value) {
      const text = String(value ?? "");
      if (/[",\n]/.test(text)) {
        return `"${text.replace(/"/g, '""')}"`;
      }
      return text;
    },

    eventDetailSections() {
      const props = this.eventDetailEvent?.props || {};
      const sections = [];
      const handledKeys = new Set();

      if (props.tls) {
        handledKeys.add("tls");
        const tlsReq = props.tls.req || {};
        const tlsResp = props.tls.resp || {};
        const section = this.buildEventDetailSection("TLS", [
          { label: "SNI", value: tlsReq.sni, mono: true },
          { label: "ALPN", value: tlsReq.alpn },
          { label: "请求版本", value: tlsReq.version, mono: true },
          { label: "响应版本", value: tlsResp.version, mono: true },
          { label: "密码套件", value: tlsResp.cipher, mono: true },
          { label: "支持版本", value: tlsReq.supported_versions, mono: true },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.http) {
        handledKeys.add("http");
        const req = props.http.req || {};
        const headers = req.headers || {};
        const resp = props.http.resp || {};
        const section = this.buildEventDetailSection("HTTP", [
          { label: "方法", value: req.method, mono: true },
          { label: "Host", value: headers.host, mono: true },
          { label: "路径", value: req.path, mono: true },
          { label: "User-Agent", value: headers["user-agent"] || headers["User-Agent"] },
          { label: "状态码", value: resp.status, mono: true },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.dns) {
        handledKeys.add("dns");
        const section = this.buildEventDetailSection("DNS", [
          {
            label: "问题名",
            value: Array.isArray(props.dns.questions)
              ? props.dns.questions.map((item) => item?.name).filter(Boolean)
              : [],
            mono: true,
          },
          { label: "是否响应", value: props.dns.qr },
          {
            label: "应答数",
            value: Array.isArray(props.dns.answers) ? props.dns.answers.length : undefined,
            mono: true,
          },
          {
            label: "权威记录数",
            value: Array.isArray(props.dns.authorities) ? props.dns.authorities.length : undefined,
            mono: true,
          },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.fet) {
        handledKeys.add("fet");
        const section = this.buildEventDetailSection("FET", [
          { label: "命中", value: props.fet.yes },
          { label: "ex1", value: props.fet.ex1, mono: true },
          { label: "ex2", value: props.fet.ex2 },
          { label: "ex3", value: props.fet.ex3, mono: true },
          { label: "ex4", value: props.fet.ex4, mono: true },
          { label: "ex5", value: props.fet.ex5 },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.trojan) {
        handledKeys.add("trojan");
        const section = this.buildEventDetailSection("Trojan", [
          { label: "命中", value: props.trojan.yes },
          { label: "序列", value: props.trojan.seq, mono: true },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.ssh) {
        handledKeys.add("ssh");
        const section = this.buildEventDetailSection("SSH", [
          { label: "客户端软件", value: props.ssh.client?.software, mono: true },
          { label: "服务端软件", value: props.ssh.server?.software, mono: true },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      if (props.quic) {
        handledKeys.add("quic");
        const section = this.buildEventDetailSection("QUIC", [
          { label: "SNI", value: props.quic.req?.sni, mono: true },
          { label: "ALPN", value: props.quic.req?.alpn },
        ]);
        if (section) {
          sections.push(section);
        }
      }

      const remaining = Object.fromEntries(
        Object.entries(props).filter(([key]) => !handledKeys.has(key))
      );
      if (Object.keys(remaining).length) {
        sections.push({
          title: "其他字段",
          rows: Object.entries(remaining).map(([key, value]) => ({
            label: key,
            value: this.formatEventDetailValue(value),
            mono: typeof value !== "object",
          })),
        });
      }

      return sections;
    },

    openEventDetail(event) {
      if (!event) {
        return;
      }
      this.eventDetailEvent = event;
      this.eventDetailDialogVisible = true;
    },

    nodePlatformKey(node) {
      const goos = String(node?.metadata?.goos || "").trim();
      const goarch = String(node?.metadata?.goarch || "").trim();
      if (!goos || !goarch) {
        return "";
      }
      return `${goos}/${goarch}`;
    },

    nodePlatformLabel(node) {
      return this.nodePlatformKey(node) || "";
    },

    openNodeInstallDialog() {
      this.resetNodeInstallFeedback();
      this.nodeInstallDialogVisible = true;
    },

    async openNodeCommandDialog(node) {
      if (!node?.id) {
        return;
      }
      this.resetNodeCommandFeedback();
      this.nodeCommandTarget = node;
      this.nodeCommandResult = null;
      this.nodeCommandDialogVisible = true;
      await this.generateNodeCommands(node.id);
    },

    openReleaseBuildDialog() {
      this.resetAgentBuildFeedback();
      this.agentBuildResults = [];
      this.agentBuildDialogVisible = true;
    },

    async copyText(value, successMessage = "已复制。") {
      const text = String(value || "");
      if (!text) {
        return;
      }
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const input = document.createElement("textarea");
        input.value = text;
        input.setAttribute("readonly", "true");
        input.style.position = "absolute";
        input.style.left = "-9999px";
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        document.body.removeChild(input);
      }
      ElementPlus.ElMessage.success(successMessage);
    },

    async copyNodeCommand(command, message) {
      if (!command) {
        return;
      }
      await this.copyText(command, message);
    },

    async buildManagedAgentBinary(force = this.agentBuildForm.force) {
      this.resetAgentBuildFeedback();
      this.agentBuildResults = [];
      const targets = (this.agentBuildForm.targets || [])
        .map((key) => this.availableBuildTargets.find((item) => item.key === key))
        .filter(Boolean)
        .map((item) => ({
          goos: item.goos,
          goarch: item.goarch,
        }));
      if (!targets.length) {
        this.agentBuildError = "请至少选择一个目标平台。";
        return;
      }
      this.agentBuildSubmitting = true;
      try {
        const result = await requestJSON("/api/v1/build/agent", {
          method: "POST",
          body: JSON.stringify({
            targets,
            force: Boolean(force),
          }),
        });
        this.agentBuildResults = result?.builds || [];
        this.agentBuildSuccess = `已处理 ${this.agentBuildResults.length} 个目标平台的 Agent 二进制。`;
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.agentBuildError = error.message || String(error);
      } finally {
        this.agentBuildSubmitting = false;
      }
    },

    async publishManagedAgentRelease() {
      this.resetAgentBuildFeedback();
      const version = String(this.agentBuildForm.releaseVersion || "").trim();
      if (!version) {
        this.agentBuildError = "发布版本不能为空。";
        return;
      }
      const targets = (this.agentBuildForm.targets || [])
        .map((key) => this.availableBuildTargets.find((item) => item.key === key))
        .filter(Boolean)
        .map((item) => ({
          goos: item.goos,
          goarch: item.goarch,
        }));
      if (!targets.length) {
        this.agentBuildError = "请至少选择一个目标平台。";
        return;
      }
      this.agentBuildSubmitting = true;
      try {
        const artifact = await requestJSON("/api/v1/releases/managed", {
          method: "POST",
          body: JSON.stringify({
            version,
            notes: String(this.agentBuildForm.releaseNotes || "").trim(),
            force: Boolean(this.agentBuildForm.force),
            targets,
          }),
        });
        this.agentBuildSuccess = `Agent 版本 ${artifact.version} 已生成并发布。`;
        this.agentBuildDialogVisible = false;
        await this.loadReleases();
        this.openReleaseDetail(artifact.version);
        ElementPlus.ElMessage.success(`Agent 版本 ${artifact.version} 已生成并发布。`);
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.agentBuildError = error.message || String(error);
      } finally {
        this.agentBuildSubmitting = false;
      }
    },

    buildNodeInstallPayload() {
      const name = String(this.nodeInstallForm.name || "").trim();

      if (!name) {
        throw new Error("节点名称不能为空。");
      }

      return {
        name,
        labels: this.parseLineList(this.nodeInstallForm.labelsText),
      };
    },

    async submitNodeInstall() {
      this.resetNodeInstallFeedback();
      this.nodeInstallSubmitting = true;
      try {
        const payload = this.buildNodeInstallPayload();
        const result = await requestJSON("/api/v1/nodes", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        const successMessage = `节点 ${result?.id || "—"} 已保存。`;
        this.nodeInstallSuccess = successMessage;
        await this.loadNodes();
        this.nodeInstallDialogVisible = false;
        ElementPlus.ElMessage.success(successMessage);
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.nodeInstallError = error.message || String(error);
      } finally {
        this.nodeInstallSubmitting = false;
      }
    },

    async generateNodeCommands(nodeId) {
      this.resetNodeCommandFeedback();
      this.nodeCommandSubmitting = true;
      try {
        this.nodeCommandResult = await requestJSON(`/api/v1/nodes/${encodeURIComponent(nodeId)}/commands`, {
          method: "POST",
        });
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.nodeCommandError = error.message || String(error);
      } finally {
        this.nodeCommandSubmitting = false;
      }
    },

    async deleteNode(node) {
      if (!node?.id) {
        return;
      }
      if (!window.confirm(`确定删除节点 ${node.name || node.id} 吗？`)) {
        return;
      }
      try {
        await requestJSON(`/api/v1/nodes/${encodeURIComponent(node.id)}`, {
          method: "DELETE",
        }, false);
        if (this.selectedNode?.id === node.id) {
          this.selectedNode = null;
          this.selectedNodeTasks = [];
          this.selectedNodeEvents = [];
          this.selectedNodeReport = null;
          this.selectedNodeTrafficSeries = [];
          this.navigateToView("nodes");
        }
        if (this.nodeCommandTarget?.id === node.id) {
          this.nodeCommandDialogVisible = false;
        }
        await this.loadNodes();
        ElementPlus.ElMessage.success(`节点 ${node.name || node.id} 已删除。`);
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        ElementPlus.ElMessage.error(error.message || String(error));
      }
    },

    openReleaseCreateDialog() {
      this.resetReleaseFeedback();
      this.releaseDialogVisible = true;
    },

    buildReleasePayload() {
      const version = String(this.releaseForm.version || "").trim();
      if (!version) {
        throw new Error("发布版本不能为空。");
      }
      return {
        version,
        downloadUrl: String(this.releaseForm.downloadUrl || "").trim(),
        checksum: String(this.releaseForm.checksum || "").trim(),
        notes: String(this.releaseForm.notes || "").trim(),
      };
    },

    async submitReleaseCreate() {
      this.resetReleaseFeedback();
      this.releaseSubmitting = true;
      try {
        const payload = this.buildReleasePayload();
        await requestJSON("/api/v1/releases", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        this.releaseSuccess = `发布包 ${payload.version} 已保存。`;
        await this.loadReleases();
        this.releaseDialogVisible = false;
        this.openReleaseDetail(payload.version);
        ElementPlus.ElMessage.success(`发布包 ${payload.version} 已保存。`);
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.releaseError = error.message || String(error);
      } finally {
        this.releaseSubmitting = false;
      }
    },

    startNewBundle() {
      this.selectedBundle = defaultBundleTemplate();
      this.activeView = "policies";
      this.detailRoute = { type: "policies", id: "__new__" };
      const nextHash = this.buildHash();
      if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
        return;
      }
    },

    syncBundleDraft(bundle) {
      const runtime = bundle?.runtime || {};
      const telemetry = bundle?.telemetry || {};
      const io = runtime.io || {};
      const workers = runtime.workers || {};
      this.bundleDraft = {
        version: bundle?.version || "",
        agentVersion: bundle?.agentVersion || "",
        readonly: Boolean(bundle?.readonly),
        runtime: {
          io: {
            queueSize: Number(io.queueSize || 0),
            rcvBuf: Number(io.rcvBuf || 0),
            sndBuf: Number(io.sndBuf || 0),
            local: Boolean(io.local),
            rst: Boolean(io.rst),
          },
          workers: {
            count: Number(workers.count || 0),
            queueSize: Number(workers.queueSize || 0),
            tcpMaxBufferedPagesTotal: Number(workers.tcpMaxBufferedPagesTotal || 0),
            tcpMaxBufferedPagesPerConn: Number(workers.tcpMaxBufferedPagesPerConn || 0),
            udpMaxStreams: Number(workers.UDPMaxStreams || workers.udpMaxStreams || 0),
          },
          extraRows: Object.entries(runtime.extra || {}).map(([key, value]) => ({
            key,
            value: String(value),
          })),
        },
        telemetry: {
          analyzers: [...(telemetry.analyzers || [])],
          events: {
            ruleHit: Boolean((telemetry.events || {}).ruleHit),
            suspiciousOnly: Boolean((telemetry.events || {}).suspiciousOnly),
            flowSummary: Boolean((telemetry.events || {}).flowSummary),
          },
          sampling: {
            benignFlow: Number((telemetry.sampling || {}).benignFlow || 0),
          },
        },
        rules: (bundle?.rules || []).map((rule) => ({
          name: rule.name || "",
          action: rule.action || "",
          log: Boolean(rule.log),
          expr: rule.expr || "",
          modifierName: rule.modifier?.name || "",
          modifierDnsA: String(rule.modifier?.args?.a || ""),
          modifierDnsAAAA: String(rule.modifier?.args?.aaaa || ""),
          modifierArgsText: rule.modifier?.args ? prettyJson(rule.modifier.args) : "",
        })),
        metadataRows: Object.entries(bundle?.metadata || {}).map(([key, value]) => ({
          key,
          value: String(value),
        })),
      };
      this.bundleSaveError = "";
      this.bundleSaveSuccess = "";
    },

    normalizeKeyValueRows(rows) {
      return (rows || []).reduce((acc, row) => {
        const key = String(row?.key || "").trim();
        if (!key) {
          return acc;
        }
        acc[key] = String(row?.value || "");
        return acc;
      }, {});
    },

    parseModifierArgs(text) {
      const source = String(text || "").trim();
      if (!source) {
        return {};
      }
      const parsed = JSON.parse(source);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("Modifier 参数必须是 JSON 对象。");
      }
      return parsed;
    },

    isLikelyIPv4(value) {
      const source = String(value || "").trim();
      if (!source) {
        return false;
      }
      return /^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$/.test(source);
    },

    isLikelyIPv6(value) {
      const source = String(value || "").trim();
      if (!source) {
        return false;
      }
      return source.includes(":") && /^[0-9a-fA-F:.]+$/.test(source);
    },

    getRuleAnalyzerDependencies(rule) {
      const expr = String(rule?.expr || "");
      const map = [
        { name: "http", pattern: /\bhttp\./ },
        { name: "tls", pattern: /\btls\./ },
        { name: "dns", pattern: /\bdns\./ },
        { name: "ssh", pattern: /\bssh\./ },
        { name: "fet", pattern: /\bfet\./ },
        { name: "trojan", pattern: /\btrojan\./ },
        { name: "quic", pattern: /\bquic\./ },
        { name: "wireguard", pattern: /\bwireguard\./ },
        { name: "openvpn", pattern: /\bopenvpn\./ },
        { name: "socks", pattern: /\bsocks\./ },
      ];
      return map.filter((item) => item.pattern.test(expr)).map((item) => item.name);
    },

    getRuleValidationIssues(rule, index) {
      const issues = [];
      const name = String(rule?.name || "").trim();
      const expr = String(rule?.expr || "").trim();
      const action = String(rule?.action || "").trim();
      const modifierName = String(rule?.modifierName || "").trim();

      if (!name) {
        issues.push(`第 ${index + 1} 条规则缺少名称。`);
      }
      if (!expr) {
        issues.push(`第 ${index + 1} 条规则缺少表达式。`);
      }
      if (!action && !rule?.log) {
        issues.push(`第 ${index + 1} 条规则至少需要动作或日志。`);
      }
      if (action === "modify" && !modifierName) {
        issues.push(`第 ${index + 1} 条规则使用 modify 时必须指定 modifier。`);
      }
      if (action !== "modify" && modifierName) {
        issues.push(`第 ${index + 1} 条规则已填写 modifier，但当前动作不是 modify。`);
      }
      if (action === "modify" && modifierName === "dns") {
        const hasDnsExpr = /\bdns\./.test(expr);
        const hasUdpExpr = /proto\s*==\s*["']udp["']/.test(expr);
        if (!hasDnsExpr) {
          issues.push(`第 ${index + 1} 条 dns 改写规则建议引用 dns.* 字段。`);
        }
        if (!hasUdpExpr) {
          issues.push(`第 ${index + 1} 条 dns 改写规则建议限制 proto == "udp"。`);
        }
        const a = String(rule?.modifierDnsA || "").trim();
        const aaaa = String(rule?.modifierDnsAAAA || "").trim();
        if (!a && !aaaa) {
          issues.push(`第 ${index + 1} 条 dns 改写规则至少填写一个 A/AAAA 目标。`);
        }
        if (a && !this.isLikelyIPv4(a)) {
          issues.push(`第 ${index + 1} 条规则的 A 记录不是合法 IPv4。`);
        }
        if (aaaa && !this.isLikelyIPv6(aaaa)) {
          issues.push(`第 ${index + 1} 条规则的 AAAA 记录不是合法 IPv6。`);
        }
      }
      if (action === "modify" && modifierName && modifierName !== "dns") {
        try {
          this.parseModifierArgs(rule?.modifierArgsText);
        } catch (error) {
          issues.push(`第 ${index + 1} 条规则 modifier 参数无效：${error.message}`);
        }
      }

      return issues;
    },

    buildBundlePayload() {
      if (!this.bundleDraft) {
        throw new Error("没有可保存的策略包草稿。");
      }

      const rules = this.bundleDraft.rules.map((rule, index) => {
        const name = String(rule.name || "").trim();
        const expr = String(rule.expr || "").trim();
        const actionName = String(rule.action || "").trim();
        if (!name) {
          throw new Error(`第 ${index + 1} 条规则缺少名称。`);
        }
        if (!expr) {
          throw new Error(`第 ${index + 1} 条规则缺少表达式。`);
        }
        if (!actionName && !rule.log) {
          throw new Error(`第 ${index + 1} 条规则至少需要动作或日志。`);
        }

        const payload = {
          name,
          log: Boolean(rule.log),
          expr,
        };
        if (actionName) {
          payload.action = actionName;
        }

        const modifierName = String(rule.modifierName || "").trim();
        if (actionName === "modify" && modifierName) {
          let args = {};
          if (modifierName === "dns") {
            const a = String(rule.modifierDnsA || "").trim();
            const aaaa = String(rule.modifierDnsAAAA || "").trim();
            if (a) {
              args.a = a;
            }
            if (aaaa) {
              args.aaaa = aaaa;
            }
          } else {
            args = this.parseModifierArgs(rule.modifierArgsText);
          }
          payload.modifier = {
            name: modifierName,
            args,
          };
        }
        return payload;
      });

      if (!String(this.bundleDraft.version || "").trim()) {
        throw new Error("策略版本不能为空。");
      }

      return {
        version: String(this.bundleDraft.version || "").trim(),
        agentVersion: String(this.bundleDraft.agentVersion || "").trim(),
        runtime: {
          io: {
            queueSize: Number(this.bundleDraft.runtime.io.queueSize || 0),
            rcvBuf: Number(this.bundleDraft.runtime.io.rcvBuf || 0),
            sndBuf: Number(this.bundleDraft.runtime.io.sndBuf || 0),
            local: Boolean(this.bundleDraft.runtime.io.local),
            rst: Boolean(this.bundleDraft.runtime.io.rst),
          },
          workers: {
            count: Number(this.bundleDraft.runtime.workers.count || 0),
            queueSize: Number(this.bundleDraft.runtime.workers.queueSize || 0),
            tcpMaxBufferedPagesTotal: Number(this.bundleDraft.runtime.workers.tcpMaxBufferedPagesTotal || 0),
            tcpMaxBufferedPagesPerConn: Number(this.bundleDraft.runtime.workers.tcpMaxBufferedPagesPerConn || 0),
            udpMaxStreams: Number(this.bundleDraft.runtime.workers.udpMaxStreams || 0),
          },
          extra: this.normalizeKeyValueRows(this.bundleDraft.runtime.extraRows),
        },
        telemetry: {
          analyzers: [...(this.bundleDraft.telemetry.analyzers || [])]
            .map((name) => String(name || "").trim())
            .filter(Boolean),
          events: {
            ruleHit: Boolean(this.bundleDraft.telemetry.events.ruleHit),
            suspiciousOnly: Boolean(this.bundleDraft.telemetry.events.suspiciousOnly),
            flowSummary: Boolean(this.bundleDraft.telemetry.events.flowSummary),
          },
          sampling: {
            benignFlow: Number(this.bundleDraft.telemetry.sampling.benignFlow || 0),
          },
        },
        rules,
        metadata: this.normalizeKeyValueRows(this.bundleDraft.metadataRows),
      };
    },

    addBundleRule() {
      if (!this.bundleDraft) {
        return;
      }
      this.bundleDraft.rules.push({
        name: "",
        action: "allow",
        log: false,
        expr: "",
        modifierName: "",
        modifierDnsA: "",
        modifierDnsAAAA: "",
        modifierArgsText: "",
      });
    },

    applyBundleRuleTemplate(template) {
      if (!this.bundleDraft) {
        return;
      }
      const cloned = JSON.parse(JSON.stringify(template.rule));
      this.bundleDraft.rules.push(cloned);
    },

    appendRuleExpr(index, snippet) {
      const rule = this.bundleDraft?.rules[index];
      if (!rule) {
        return;
      }
      const current = String(rule.expr || "").trim();
      rule.expr = current ? `${current} && ${snippet}` : snippet;
    },

    describeRuleAction(action) {
      return RULE_ACTION_HELP[String(action || "")] || RULE_ACTION_HELP[""];
    },

    policyFieldHelp(key) {
      return POLICY_FIELD_HELP[key] || "";
    },

    resetRuleWizard() {
      this.ruleWizardStep = 0;
      this.ruleWizard = {
        scenario: "tls_sni",
        name: "",
        action: "block",
        log: false,
        domain: "",
        geosite: "category-ads-all",
        cidr: "",
        cidrSide: "either",
        rewriteIPv4: "127.0.0.1",
        rewriteIPv6: "::1",
      };
    },

    setRuleWizardStep(step) {
      const max = this.ruleWizardSteps.length - 1;
      this.ruleWizardStep = Math.min(Math.max(step, 0), max);
    },

    nextRuleWizardStep() {
      if (!this.canAdvanceRuleWizardStep) {
        return;
      }
      this.setRuleWizardStep(this.ruleWizardStep + 1);
    },

    prevRuleWizardStep() {
      this.setRuleWizardStep(this.ruleWizardStep - 1);
    },

    getRuleWizardStepIssues(step) {
      const issues = [];
      const name = String(this.ruleWizard.name || "").trim();
      if (step === 0) {
        if (!this.currentRuleWizardMeta) {
          issues.push("请选择一个规则场景。");
        }
        return issues;
      }

      if (step === 1) {
        if (!name) {
          issues.push("规则名称不能为空。");
        }
        if (this.ruleWizard.scenario === "tls_sni" && !String(this.ruleWizard.domain || "").trim()) {
          issues.push("请填写要匹配的 TLS SNI 域名。");
        }
        if (this.ruleWizard.scenario === "http_host" && !String(this.ruleWizard.domain || "").trim()) {
          issues.push("请填写要匹配的 HTTP Host。");
        }
        if (this.ruleWizard.scenario === "dns_qname" && !String(this.ruleWizard.domain || "").trim()) {
          issues.push("请填写要匹配的 DNS 域名。");
        }
        if (this.ruleWizard.scenario === "geosite_sni" && !String(this.ruleWizard.geosite || "").trim()) {
          issues.push("请填写 GeoSite 列表名。");
        }
        if (this.ruleWizard.scenario === "cidr_ip" && !String(this.ruleWizard.cidr || "").trim()) {
          issues.push("请填写 CIDR 网段。");
        }
        return issues;
      }

      if (step === 2) {
        if (!String(this.ruleWizard.action || "").trim() && !this.ruleWizard.log) {
          issues.push("动作和日志至少需要开启一个。");
        }
        if (this.ruleWizard.scenario === "dns_qname" && this.ruleWizard.action === "modify") {
          const hasA = String(this.ruleWizard.rewriteIPv4 || "").trim();
          const hasAAAA = String(this.ruleWizard.rewriteIPv6 || "").trim();
          if (!hasA && !hasAAAA) {
            issues.push("DNS 改写至少填写一个 A / AAAA 目标。");
          }
          if (hasA && !this.isLikelyIPv4(hasA)) {
            issues.push("DNS 改写的 A 记录不是合法 IPv4。");
          }
          if (hasAAAA && !this.isLikelyIPv6(hasAAAA)) {
            issues.push("DNS 改写的 AAAA 记录不是合法 IPv6。");
          }
        }
      }

      return issues;
    },

    buildRuleFromWizard() {
      const scenario = this.ruleWizard.scenario;
      const name = String(this.ruleWizard.name || "").trim();
      const action = String(this.ruleWizard.action || "").trim();
      let expr = "true";
      let modifierName = "";
      let modifierDnsA = "";
      let modifierDnsAAAA = "";

      if (scenario === "tls_sni") {
        const domain = String(this.ruleWizard.domain || "").trim();
        expr = `tls.req.sni != nil && tls.req.sni == "${domain}"`;
      } else if (scenario === "http_host") {
        const domain = String(this.ruleWizard.domain || "").trim();
        expr = `http.req.headers.host == "${domain}"`;
      } else if (scenario === "dns_qname") {
        const domain = String(this.ruleWizard.domain || "").trim();
        expr = `proto == "udp" && dns.qr == true && dns.questions != nil && len(dns.questions) > 0 && dns.questions[0].name == "${domain}"`;
        if (action === "modify") {
          modifierName = "dns";
          modifierDnsA = String(this.ruleWizard.rewriteIPv4 || "").trim();
          modifierDnsAAAA = String(this.ruleWizard.rewriteIPv6 || "").trim();
        }
      } else if (scenario === "geosite_sni") {
        const group = String(this.ruleWizard.geosite || "").trim();
        expr = `tls.req.sni != nil && geosite(tls.req.sni, "${group}")`;
      } else if (scenario === "cidr_ip") {
        const cidr = String(this.ruleWizard.cidr || "").trim();
        if (this.ruleWizard.cidrSide === "src") {
          expr = `cidr(ip.src, "${cidr}")`;
        } else if (this.ruleWizard.cidrSide === "dst") {
          expr = `cidr(ip.dst, "${cidr}")`;
        } else {
          expr = `cidr(ip.src, "${cidr}") || cidr(ip.dst, "${cidr}")`;
        }
      } else if (scenario === "fet_proxy") {
        expr = "fet.yes == true";
      }

      return {
        name,
        action,
        log: Boolean(this.ruleWizard.log),
        expr,
        modifierName,
        modifierDnsA,
        modifierDnsAAAA,
        modifierArgsText: "",
      };
    },

    applyRuleWizard() {
      if (!this.bundleDraft || this.ruleWizardIssues.length) {
        return;
      }
      this.bundleDraft.rules.push(this.buildRuleFromWizard());
      this.resetRuleWizard();
    },

    duplicateBundleRule(index) {
      if (!this.bundleDraft?.rules[index]) {
        return;
      }
      const cloned = JSON.parse(JSON.stringify(this.bundleDraft.rules[index]));
      cloned.name = `${cloned.name || "rule"}-copy`;
      this.bundleDraft.rules.splice(index + 1, 0, cloned);
    },

    removeBundleRule(index) {
      if (!this.bundleDraft) {
        return;
      }
      this.bundleDraft.rules.splice(index, 1);
    },

    moveBundleRule(index, direction) {
      if (!this.bundleDraft) {
        return;
      }
      const target = index + direction;
      if (target < 0 || target >= this.bundleDraft.rules.length) {
        return;
      }
      const [rule] = this.bundleDraft.rules.splice(index, 1);
      this.bundleDraft.rules.splice(target, 0, rule);
    },

    addBundleMetadataRow(target = "metadata") {
      if (!this.bundleDraft) {
        return;
      }
      const row = { key: "", value: "" };
      if (target === "runtimeExtra") {
        this.bundleDraft.runtime.extraRows.push(row);
        return;
      }
      this.bundleDraft.metadataRows.push(row);
    },

    removeBundleMetadataRow(index, target = "metadata") {
      if (!this.bundleDraft) {
        return;
      }
      if (target === "runtimeExtra") {
        this.bundleDraft.runtime.extraRows.splice(index, 1);
        return;
      }
      this.bundleDraft.metadataRows.splice(index, 1);
    },

    resetBundleDraft() {
      if (this.selectedBundle) {
        this.syncBundleDraft(this.selectedBundle);
      }
    },

    async saveBundleDraft() {
      this.bundleSaveError = "";
      this.bundleSaveSuccess = "";
      if (this.selectedBundleReadonly) {
        this.bundleSaveError = "系统默认上报策略不可修改。";
        return;
      }
      this.bundleSaving = true;
      try {
        const payload = this.buildBundlePayload();
        await requestJSON("/api/v1/policies/bundles", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        this.bundleSaveSuccess = `策略包 ${payload.version} 已保存。`;
        await this.loadBundles();
        await this.selectBundle(payload.version);
        this.openBundleDetail(payload.version);
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.bundleSaveError = error.message || String(error);
      } finally {
        this.bundleSaving = false;
      }
    },

    async loadRolloutNodes() {
      const result = await requestJSON("/api/v1/nodes?limit=200");
      this.rolloutNodes = result?.nodes || [];
      this.bundleRolloutTargetIds = this.bundleRolloutTargetIds.filter((id) =>
        this.rolloutNodes.some((node) => node.id === id)
      );
      this.releaseRolloutTargetIds = this.releaseRolloutTargetIds.filter((id) =>
        this.rolloutNodes.some((node) => node.id === id)
      );
    },

    selectOnlineRolloutNodes() {
      this.bundleRolloutTargetIds = [...this.rolloutOnlineNodeIds];
    },

    clearRolloutSelection() {
      this.bundleRolloutTargetIds = [];
    },

    async submitBundleRollout() {
      this.bundleRolloutError = "";
      this.bundleRolloutSuccess = "";
      if (!this.selectedBundle?.version) {
        this.bundleRolloutError = "当前没有可下发的策略版本。";
        return;
      }
      if (!this.bundleRolloutTargetIds.length) {
        this.bundleRolloutError = "请至少选择一个节点。";
        return;
      }

      const targetIds = [...this.bundleRolloutTargetIds];
      this.setBundleNodeOperation(targetIds, "applying");
      this.bundleRolloutSubmitting = true;
      try {
        const result = await requestJSON("/api/v1/policies/rollouts", {
          method: "POST",
          body: JSON.stringify({
            bundleVersion: this.selectedBundle.version,
            agentIds: targetIds,
          }),
        });
        const accepted = (result?.tasks || []).length;
        const sync = await this.waitForNodeBundleState(
          targetIds,
          (node) => String(node?.bundleVersion || "").trim() === String(this.selectedBundle.version || "").trim()
        );
        await this.loadNodes();
        if (sync.complete) {
          this.bundleRolloutSuccess = `已下发 ${accepted} 个任务，${targetIds.length} 个节点已生效。`;
        } else {
          this.bundleRolloutSuccess = `已下发 ${accepted} 个任务，${sync.matchedIds.length} 个节点已生效，${sync.pendingIds.length} 个节点等待回报。`;
        }
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.bundleRolloutError = error.message || String(error);
      } finally {
        this.bundleRolloutSubmitting = false;
        this.clearBundleNodeOperation(targetIds);
      }
    },

    async removeNodeFromSelectedBundle(node) {
      if (!this.selectedBundle?.version || !node?.id) {
        return;
      }
      if (String(node.bundleVersion || "").trim() !== String(this.selectedBundle.version || "").trim()) {
        return;
      }
      if (!window.confirm(`确定将节点 ${node.name || node.id} 从当前策略中移除吗？移除后该节点会切回系统默认上报策略。`)) {
        return;
      }
      this.bundleRolloutError = "";
      this.bundleRolloutSuccess = "";
      this.setBundleNodeOperation([node.id], "removing");
      this.bundleDetachSubmittingId = node.id;
      try {
        await requestJSON("/api/v1/policies/rollouts", {
          method: "POST",
          body: JSON.stringify({
            bundleVersion: DEFAULT_REPORTING_BUNDLE_VERSION,
            agentIds: [node.id],
          }),
        });
        const sync = await this.waitForNodeBundleState(
          [node.id],
          (currentNode) => String(currentNode?.bundleVersion || "").trim() === DEFAULT_REPORTING_BUNDLE_VERSION
        );
        await this.loadNodes();
        if (sync.complete) {
          this.bundleRolloutSuccess = `已将节点 ${node.name || node.id} 从当前策略移除。`;
        } else {
          this.bundleRolloutSuccess = `已下发移除任务，节点 ${node.name || node.id} 正等待状态回报。`;
        }
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.bundleRolloutError = error.message || String(error);
      } finally {
        this.bundleDetachSubmittingId = "";
        this.clearBundleNodeOperation([node.id]);
      }
    },

    selectOnlineReleaseRolloutNodes() {
      this.releaseRolloutTargetIds = [...this.rolloutOnlineNodeIds];
    },

    selectUpgradeableReleaseRolloutNodes() {
      this.releaseRolloutTargetIds = [...this.releaseUpgradeableNodeIds];
    },

    clearReleaseRolloutSelection() {
      this.releaseRolloutTargetIds = [];
    },

    async submitReleaseRollout() {
      this.releaseRolloutError = "";
      this.releaseRolloutSuccess = "";
      if (!this.selectedRelease?.version) {
        this.releaseRolloutError = "当前没有可下发的发布版本。";
        return;
      }
      if (!this.releaseRolloutTargetIds.length) {
        this.releaseRolloutError = "请至少选择一个节点。";
        return;
      }

      this.releaseRolloutSubmitting = true;
      try {
        const result = await requestJSON("/api/v1/releases/rollouts", {
          method: "POST",
          body: JSON.stringify({
            version: this.selectedRelease.version,
            agentIds: this.releaseRolloutTargetIds,
          }),
        });
        const accepted = (result?.tasks || []).length;
        this.releaseRolloutSuccess = `已下发 ${accepted} 个升级任务到 ${this.releaseRolloutTargetIds.length} 个节点。`;
        await this.loadNodes();
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.releaseRolloutError = error.message || String(error);
      } finally {
        this.releaseRolloutSubmitting = false;
      }
    },

    buildHash(view = this.activeView, detailType = this.detailRoute.type, detailId = this.detailRoute.id) {
      if (detailType && detailId) {
        return `#/${detailType}/${encodeURIComponent(detailId)}`;
      }
      return `#/${view}`;
    },

    applyHashRoute() {
      const raw = (window.location.hash || "").replace(/^#\/?/, "");
      if (!raw) {
        this.activeView = "overview";
        this.detailRoute = { type: "", id: "" };
        return;
      }

      const parts = raw.split("/");
      const view = VIEW_META[parts[0]] ? parts[0] : "overview";
      if (["nodes", "policies", "releases"].includes(view) && parts.length > 1) {
        this.activeView = view;
        this.detailRoute = {
          type: view,
          id: decodeURIComponent(parts.slice(1).join("/")),
        };
        return;
      }

      this.activeView = view;
      this.detailRoute = { type: "", id: "" };
    },

    updateHash(replace = false) {
      const nextHash = this.buildHash();
      if (replace) {
        window.history.replaceState(null, "", nextHash);
        return;
      }
      if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
      }
    },

    async syncDetailRoute() {
      if (!this.auth.authenticated) {
        return;
      }

      if (this.detailRoute.type === "nodes" && this.detailRoute.id) {
        await this.selectNode(this.detailRoute.id);
        return;
      }
      if (this.detailRoute.type === "policies" && this.detailRoute.id) {
        if (this.detailRoute.id === "__new__") {
          if (!this.selectedBundle || this.selectedBundle.version) {
            this.selectedBundle = defaultBundleTemplate();
          }
          return;
        }
        await this.selectBundle(this.detailRoute.id);
        return;
      }
      if (this.detailRoute.type === "releases" && this.detailRoute.id) {
        await this.selectRelease(this.detailRoute.id);
      }
    },

    navigateToView(view) {
      this.activeView = view;
      this.detailRoute = { type: "", id: "" };
      this.updateHash();
    },

    openNodeDetail(nodeId) {
      this.activeView = "nodes";
      this.detailRoute = { type: "nodes", id: nodeId };
      const nextHash = this.buildHash();
      if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
        return;
      }
      this.syncDetailRoute().catch((error) => {
        ElementPlus.ElMessage.error(error.message || String(error));
      });
    },

    openBundleDetail(version) {
      this.activeView = "policies";
      this.detailRoute = { type: "policies", id: version };
      const nextHash = this.buildHash();
      if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
        return;
      }
      this.syncDetailRoute().catch((error) => {
        ElementPlus.ElMessage.error(error.message || String(error));
      });
    },

    openReleaseDetail(version) {
      this.activeView = "releases";
      this.detailRoute = { type: "releases", id: version };
      const nextHash = this.buildHash();
      if (window.location.hash !== nextHash) {
        window.location.hash = nextHash;
        return;
      }
      this.syncDetailRoute().catch((error) => {
        ElementPlus.ElMessage.error(error.message || String(error));
      });
    },

    applyAuthStatus(status) {
      if (status && status.sessionToken) {
        saveSessionToken(status.sessionToken);
      } else if (!status || !status.authenticated) {
        saveSessionToken("");
      }
      this.auth = {
        ...defaultAuth(),
        ...(status || {}),
      };
      if (this.auth.authenticated) {
        this.statusText = "主控在线";
        this.statusState = "success";
        return;
      }
      if (this.auth.setupRequired) {
        this.statusText = "待初始化";
        this.statusState = "warning";
        return;
      }
      this.statusText = "待登录";
      this.statusState = "idle";
    },

    async refreshAuthStatus() {
      const status = await requestJSON("/api/v1/auth/status");
      this.applyAuthStatus(status);
      return this.auth;
    },

    async confirmSessionEstablished() {
      const delays = [0, 50, 150, 300];
      let lastError = null;
      for (const delay of delays) {
        if (delay > 0) {
          await sleep(delay);
        }
        try {
          const auth = await this.refreshAuthStatus();
          if (auth.authenticated) {
            return auth;
          }
        } catch (error) {
          lastError = error;
        }
      }
      if (lastError) {
        throw lastError;
      }
      return this.auth;
    },

    resetAuthForms() {
      this.setupForm.password = "";
      this.setupForm.confirmPassword = "";
      this.loginForm.password = "";
    },

    handleUnauthorized() {
      saveSessionToken("");
      this.auth = defaultAuth();
      this.statusState = "idle";
      this.statusText = "登录已失效";
      this.accountDialogVisible = false;
      this.stopOverviewAutoRefresh();
      this.resetAccountFeedback();
      this.resetAuthForms();
      this.refreshAuthStatus().catch(() => {});
      ElementPlus.ElMessage.warning("登录状态已失效，请重新登录。");
    },

    async bootstrap() {
      try {
        await this.refreshAuthStatus();
        if (this.auth.authenticated) {
          await this.refreshAll(true);
          this.updateHash(true);
          this.startOverviewAutoRefresh();
        }
      } catch (error) {
        this.authError = error.message || String(error);
        this.statusText = "认证检查失败";
        this.statusState = "degraded";
      } finally {
        this.booting = false;
        this.startOverviewAutoRefresh();
      }
    },

    async submitSetup() {
      this.authError = "";
      if (!this.setupForm.username.trim()) {
        this.authError = "管理员账号不能为空。";
        return;
      }
      if (!this.setupForm.password) {
        this.authError = "管理员密码不能为空。";
        return;
      }
      if (this.setupForm.password.length < 8) {
        this.authError = "管理员密码至少需要 8 位。";
        return;
      }
      if (this.setupForm.password !== this.setupForm.confirmPassword) {
        this.authError = "两次输入的密码不一致。";
        return;
      }

      this.authSubmitting = true;
      try {
        const status = await requestJSON("/api/v1/auth/setup", {
          method: "POST",
          body: JSON.stringify({
            username: this.setupForm.username.trim(),
            password: this.setupForm.password,
          }),
        });
        this.applyAuthStatus(status);
        this.resetAuthForms();
        const auth = await this.confirmSessionEstablished();
        if (!auth.authenticated) {
          this.authError = "初始化已完成，但浏览器没有保存登录会话，请检查是否禁用了 Cookie。";
          return;
        }
        await this.refreshAll(true);
        this.updateHash(true);
        this.startOverviewAutoRefresh();
      } catch (error) {
        if (error && error.status === 409) {
          this.loginForm.username = this.setupForm.username.trim();
          try {
            await this.refreshAuthStatus();
          } catch (_) {
            // ignore
          }
          this.authError = "管理员已配置，请使用现有账号登录。";
          return;
        }
        this.authError = error.message || String(error);
      } finally {
        this.authSubmitting = false;
      }
    },

    async submitLogin() {
      this.authError = "";
      if (!this.loginForm.username.trim()) {
        this.authError = "管理员账号不能为空。";
        return;
      }
      if (!this.loginForm.password) {
        this.authError = "管理员密码不能为空。";
        return;
      }
      this.authSubmitting = true;
      try {
        const status = await requestJSON("/api/v1/auth/login", {
          method: "POST",
          body: JSON.stringify({
            username: this.loginForm.username.trim(),
            password: this.loginForm.password,
          }),
        });
        this.applyAuthStatus(status);
        this.resetAuthForms();
        const auth = await this.confirmSessionEstablished();
        if (!auth.authenticated) {
          this.authError = "登录已通过，但浏览器没有保存登录会话，请检查是否禁用了 Cookie。";
          return;
        }
        await this.refreshAll(true);
        this.updateHash(true);
        this.startOverviewAutoRefresh();
      } catch (error) {
        if (error && error.status === 409) {
          try {
            await this.refreshAuthStatus();
          } catch (_) {
            // ignore
          }
          this.authError = "尚未完成初始化，请先创建管理员账号。";
          return;
        }
        this.authError = error.message || String(error);
      } finally {
        this.authSubmitting = false;
      }
    },

    async logout() {
      try {
        await requestJSON("/api/v1/auth/logout", { method: "POST" }, false);
      } catch (_) {
        // ignore
      }
      this.accountDialogVisible = false;
      saveSessionToken("");
      this.auth = {
        ...defaultAuth(),
        setupRequired: false,
      };
      this.statusState = "idle";
      this.statusText = "已退出登录";
      this.stopOverviewAutoRefresh();
      this.resetAccountFeedback();
      this.resetAuthForms();
      this.passwordForm = {
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      };
    },

    async submitPasswordChange() {
      this.resetAccountFeedback();
      if (!this.passwordForm.currentPassword) {
        this.accountError = "请输入当前密码。";
        return;
      }
      if (!this.passwordForm.newPassword) {
        this.accountError = "请输入新密码。";
        return;
      }
      if (this.passwordForm.newPassword.length < 8) {
        this.accountError = "新密码至少需要 8 位。";
        return;
      }
      if (this.passwordForm.newPassword !== this.passwordForm.confirmPassword) {
        this.accountError = "两次输入的新密码不一致。";
        return;
      }
      if (this.passwordForm.currentPassword === this.passwordForm.newPassword) {
        this.accountError = "新密码不能与当前密码相同。";
        return;
      }
      this.passwordSubmitting = true;
      try {
        await requestJSON("/api/v1/admin/password", {
          method: "POST",
          body: JSON.stringify({
            currentPassword: this.passwordForm.currentPassword,
            newPassword: this.passwordForm.newPassword,
          }),
        }, false);
        this.accountSuccess = "密码已更新，新密码已立即生效。";
        this.passwordForm = {
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        };
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.accountError = this.formatPasswordChangeError(error);
      } finally {
        this.passwordSubmitting = false;
      }
    },

    handleMenuSelect(view) {
      this.navigateToView(view);
    },

    shouldRunOverviewAutoRefresh() {
      return Boolean(this.auth.authenticated && this.activeView === "overview" && !this.booting);
    },

    stopOverviewAutoRefresh() {
      if (this.overviewRefreshTimer) {
        window.clearInterval(this.overviewRefreshTimer);
        this.overviewRefreshTimer = null;
      }
    },

    startOverviewAutoRefresh() {
      if (!this.shouldRunOverviewAutoRefresh()) {
        this.stopOverviewAutoRefresh();
        return;
      }
      if (this.overviewRefreshTimer) {
        return;
      }
      this.refreshOverviewLive();
      this.overviewRefreshTimer = window.setInterval(() => {
        this.refreshOverviewLive();
      }, this.overviewRefreshIntervalMs);
    },

    async refreshOverviewLive() {
      if (!this.shouldRunOverviewAutoRefresh() || this.overviewLiveRefreshing || this.isRefreshing) {
        return;
      }
      this.overviewLiveRefreshing = true;
      try {
        await this.loadOverview({ background: true });
        this.lastSyncAt = new Date();
        this.statusState = "success";
        this.statusText = "主控在线";
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.statusState = "degraded";
        this.statusText = "状态降级";
      } finally {
        this.overviewLiveRefreshing = false;
      }
    },

    async refreshAll(silent = false) {
      if (!this.auth.authenticated || this.isRefreshing) {
        return;
      }

      this.isRefreshing = true;
      this.statusState = "syncing";
      this.statusText = "同步中";

      try {
        await Promise.all([
          this.loadOverview(),
          this.loadNodes(),
          this.loadBundles(),
          this.loadReleases(),
          this.loadEventRows(),
        ]);
        await this.syncDetailRoute();
        this.lastSyncAt = new Date();
        this.statusState = "success";
        this.statusText = "主控在线";
        if (!silent) {
          ElementPlus.ElMessage.success("数据已刷新。");
        }
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        this.statusState = "degraded";
        this.statusText = "状态降级";
        ElementPlus.ElMessage.error(error.message || String(error));
      } finally {
        this.isRefreshing = false;
      }
    },

    async loadOverview(options = {}) {
      const background = Boolean(options.background);
      if (!background) {
        this.loading.overview = true;
      }
      try {
        const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const [summary, suspicious, rules, protocols, trafficSeries, nodeStats] = await Promise.all([
          requestJSON("/api/v1/reports/summary"),
          requestJSON("/api/v1/reports/suspicious?limit=8"),
          requestJSON("/api/v1/reports/rules?limit=8"),
          requestJSON("/api/v1/reports/protocols"),
          requestJSON(`/api/v1/reports/series/traffic?since=${encodeURIComponent(since)}&limit=120`),
          requestJSON("/api/v1/reports/nodes"),
        ]);

        this.summary = summary || this.summary;
        this.suspiciousEvents = suspicious?.events || [];
        this.rules = rules || [];
        this.protocols = protocols || [];
        this.trafficSeries = trafficSeries?.buckets || [];
        this.nodeStats = nodeStats || [];
      } finally {
        if (!background) {
          this.loading.overview = false;
        }
      }
    },

    async loadNodes() {
      this.loading.nodes = true;
      try {
        const params = new URLSearchParams({ limit: "100" });
        if (this.filters.nodes.status) {
          params.set("status", this.filters.nodes.status);
        }
        if (this.filters.nodes.label.trim()) {
          params.set("label", this.filters.nodes.label.trim());
        }
        if (this.filters.nodes.search.trim()) {
          params.set("search", this.filters.nodes.search.trim());
        }

        const result = await requestJSON(`/api/v1/nodes?${params.toString()}`);
        this.nodes = result?.nodes || [];

        if (!this.nodes.length && !this.isNodeDetailPage) {
          this.selectedNode = null;
          this.selectedNodeTasks = [];
          this.selectedNodeEvents = [];
          this.selectedNodeReport = null;
          this.selectedNodeTrafficSeries = [];
        }
      } finally {
        this.loading.nodes = false;
      }
    },

    async resetNodeFilters() {
      this.filters.nodes.status = "";
      this.filters.nodes.label = "";
      this.filters.nodes.search = "";
      await this.loadNodes();
    },

    async handleNodeRowClick(row) {
      if (row?.id) {
        this.openNodeDetail(row.id);
      }
    },

    async loadSelectedNodeEvents(nodeId) {
      const result = await requestJSON(`/api/v1/reports/events?agentId=${encodeURIComponent(nodeId)}&limit=20`);
      this.selectedNodeEvents = result?.events || [];
    },

    async restoreNodeDefaultBundle() {
      if (!this.selectedNode?.id) {
        return;
      }
      if (!window.confirm(`确定将节点 ${this.selectedNode.name || this.selectedNode.id} 恢复为系统默认上报策略吗？`)) {
        return;
      }
      try {
        await requestJSON("/api/v1/policies/rollouts", {
          method: "POST",
          body: JSON.stringify({
            bundleVersion: DEFAULT_REPORTING_BUNDLE_VERSION,
            agentIds: [this.selectedNode.id],
          }),
        });
        await Promise.all([
          this.loadNodes(),
          this.selectNode(this.selectedNode.id),
        ]);
        ElementPlus.ElMessage.success("已下发恢复任务，节点执行后会切回系统默认上报策略。");
      } catch (error) {
        if (this.isUnauthorized(error)) {
          this.handleUnauthorized();
          return;
        }
        ElementPlus.ElMessage.error(error.message || String(error));
      }
    },

    async loadSelectedNodeTrafficSeries(nodeId) {
      const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
      const result = await requestJSON(`/api/v1/reports/series/traffic?agentId=${encodeURIComponent(nodeId)}&since=${encodeURIComponent(since)}&limit=120`);
      this.selectedNodeTrafficSeries = result?.buckets || [];
    },

    async loadEventRows() {
      this.loading.eventsView = true;
      try {
        const params = new URLSearchParams({
          limit: String(this.eventRowsPageSize),
          offset: String((this.eventRowsPage - 1) * this.eventRowsPageSize),
        });
        if (this.filters.eventsView.search.trim()) {
          params.set("search", this.filters.eventsView.search.trim());
        }
        if (this.filters.eventsView.agentId.trim()) {
          params.set("agentId", this.filters.eventsView.agentId.trim());
        }
        if (this.filters.eventsView.type) {
          params.set("type", this.filters.eventsView.type);
        }
        if (this.filters.eventsView.proto) {
          params.set("proto", this.filters.eventsView.proto);
        }
        if (this.filters.eventsView.ruleName.trim()) {
          params.set("ruleName", this.filters.eventsView.ruleName.trim());
        }
        if (this.filters.eventsView.action) {
          params.set("action", this.filters.eventsView.action);
        }
        if (this.filters.eventsView.srcIp.trim()) {
          params.set("srcIp", this.filters.eventsView.srcIp.trim());
        }
        if (this.filters.eventsView.dstIp.trim()) {
          params.set("dstIp", this.filters.eventsView.dstIp.trim());
        }
        if (String(this.filters.eventsView.port || "").trim()) {
          params.set("port", String(this.filters.eventsView.port).trim());
        }
        if (Number(this.filters.eventsView.minSuspicion || 0) > 0) {
          params.set("minSuspicion", String(Number(this.filters.eventsView.minSuspicion || 0)));
        }
        const since = this.normalizeDateFilter(this.filters.eventsView.since);
        const until = this.normalizeDateFilter(this.filters.eventsView.until);
        if (since) {
          params.set("since", since);
        }
        if (until) {
          params.set("until", until);
        }
        const result = await requestJSON(`/api/v1/reports/events?${params.toString()}`);
        this.eventRows = result?.events || [];
        this.eventRowsTotal = Number(result?.total || 0);
      } finally {
        this.loading.eventsView = false;
      }
    },

    async resetEventFilters() {
      this.eventRowsPage = 1;
      this.filters.eventsView.agentId = "";
      this.filters.eventsView.search = "";
      this.filters.eventsView.type = "";
      this.filters.eventsView.proto = "";
      this.filters.eventsView.ruleName = "";
      this.filters.eventsView.action = "";
      this.filters.eventsView.srcIp = "";
      this.filters.eventsView.dstIp = "";
      this.filters.eventsView.port = "";
      this.filters.eventsView.minSuspicion = 0;
      this.filters.eventsView.since = "";
      this.filters.eventsView.until = "";
      await this.loadEventRows();
    },

    async applyEventFilters() {
      this.eventRowsPage = 1;
      await this.loadEventRows();
    },

    async handleEventPageChange(page) {
      this.eventRowsPage = page;
      await this.loadEventRows();
    },

    async handleEventPageSizeChange(size) {
      this.eventRowsPageSize = size;
      this.eventRowsPage = 1;
      await this.loadEventRows();
    },

    async exportEventRows() {
      const params = new URLSearchParams({
        limit: "5000",
        offset: "0",
      });
      if (this.filters.eventsView.search.trim()) {
        params.set("search", this.filters.eventsView.search.trim());
      }
      if (this.filters.eventsView.agentId.trim()) {
        params.set("agentId", this.filters.eventsView.agentId.trim());
      }
      if (this.filters.eventsView.type) {
        params.set("type", this.filters.eventsView.type);
      }
      if (this.filters.eventsView.proto) {
        params.set("proto", this.filters.eventsView.proto);
      }
      if (this.filters.eventsView.ruleName.trim()) {
        params.set("ruleName", this.filters.eventsView.ruleName.trim());
      }
      if (this.filters.eventsView.action) {
        params.set("action", this.filters.eventsView.action);
      }
      if (this.filters.eventsView.srcIp.trim()) {
        params.set("srcIp", this.filters.eventsView.srcIp.trim());
      }
      if (this.filters.eventsView.dstIp.trim()) {
        params.set("dstIp", this.filters.eventsView.dstIp.trim());
      }
      if (String(this.filters.eventsView.port || "").trim()) {
        params.set("port", String(this.filters.eventsView.port).trim());
      }
      if (Number(this.filters.eventsView.minSuspicion || 0) > 0) {
        params.set("minSuspicion", String(Number(this.filters.eventsView.minSuspicion || 0)));
      }
      const since = this.normalizeDateFilter(this.filters.eventsView.since);
      const until = this.normalizeDateFilter(this.filters.eventsView.until);
      if (since) {
        params.set("since", since);
      }
      if (until) {
        params.set("until", until);
      }
      const result = await requestJSON(`/api/v1/reports/events?${params.toString()}`);
      const rows = result?.events || [];
      const headers = ["time", "agentId", "eventId", "streamId", "type", "proto", "action", "ruleName", "suspicion", "srcIp", "srcPort", "dstIp", "dstPort", "summary"];
      const lines = [headers.join(",")];
      rows.forEach((event) => {
        lines.push([
          this.escapeCsv(event.time),
          this.escapeCsv(event.agentId),
          this.escapeCsv(event.eventId),
          this.escapeCsv(event.streamId),
          this.escapeCsv(event.type),
          this.escapeCsv(event.proto),
          this.escapeCsv(event.action),
          this.escapeCsv(event.ruleName),
          this.escapeCsv(event.suspicion),
          this.escapeCsv(event.srcIp),
          this.escapeCsv(event.srcPort),
          this.escapeCsv(event.dstIp),
          this.escapeCsv(event.dstPort),
          this.escapeCsv(this.eventPropsSummary(event)),
        ].join(","));
      });
      const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `events-${new Date().toISOString().replace(/[:]/g, "-")}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
      ElementPlus.ElMessage.success(`已导出 ${rows.length} 条事件。`);
    },

    async selectNode(nodeId) {
      const [node, tasks, events, nodeStats, trafficSeries] = await Promise.all([
        requestJSON(`/api/v1/nodes/${encodeURIComponent(nodeId)}`),
        requestJSON(`/api/v1/agents/${encodeURIComponent(nodeId)}/tasks?status=all&limit=20`),
        requestJSON(`/api/v1/reports/events?agentId=${encodeURIComponent(nodeId)}&limit=20`),
        requestJSON("/api/v1/reports/nodes"),
        requestJSON(`/api/v1/reports/series/traffic?agentId=${encodeURIComponent(nodeId)}&since=${encodeURIComponent(new Date(Date.now() - 60 * 60 * 1000).toISOString())}&limit=120`),
      ]);
      this.selectedNode = node;
      this.selectedNodeTasks = tasks?.tasks || [];
      this.selectedNodeEvents = events?.events || [];
      this.selectedNodeReport = (nodeStats || []).find((item) => item.agentId === nodeId) || null;
      this.selectedNodeTrafficSeries = trafficSeries?.buckets || [];
    },

    async loadBundles() {
      this.loading.bundles = true;
      try {
        const params = new URLSearchParams({ limit: "100" });
        if (this.filters.bundles.search.trim()) {
          params.set("search", this.filters.bundles.search.trim());
        }

        const result = await requestJSON(`/api/v1/policies/bundles?${params.toString()}`);
        this.bundles = result?.bundles || [];

        if (!this.bundles.length && !this.isPolicyDetailPage) {
          this.selectedBundle = null;
        }
      } finally {
        this.loading.bundles = false;
      }
    },

    async handleBundleRowClick(row) {
      if (row?.version) {
        this.openBundleDetail(row.version);
      }
    },

    async selectBundle(version) {
      this.selectedBundle = await requestJSON(`/api/v1/policies/bundles/${encodeURIComponent(version)}`);
      await this.loadRolloutNodes();
    },

    async loadReleases() {
      this.loading.releases = true;
      try {
        const params = new URLSearchParams({ limit: "100" });
        if (this.filters.releases.search.trim()) {
          params.set("search", this.filters.releases.search.trim());
        }

        const result = await requestJSON(`/api/v1/releases?${params.toString()}`);
        this.releases = result?.artifacts || [];

        if (!this.releases.length && !this.isReleaseDetailPage) {
          this.selectedRelease = null;
        }
      } finally {
        this.loading.releases = false;
      }
    },

    async handleReleaseRowClick(row) {
      if (row?.version) {
        this.openReleaseDetail(row.version);
      }
    },

    async selectRelease(version) {
      this.selectedRelease = await requestJSON(`/api/v1/releases/${encodeURIComponent(version)}`);
      await this.loadRolloutNodes();
    },
  },
  mounted() {
    this.applyHashRoute();
    this.routeChangeHandler = async () => {
      this.applyHashRoute();
      try {
        await this.syncDetailRoute();
      } catch (error) {
        ElementPlus.ElMessage.error(error.message || String(error));
      }
      this.startOverviewAutoRefresh();
    };
    window.addEventListener("hashchange", this.routeChangeHandler);
    this.visibilityChangeHandler = () => {
      if (document.visibilityState === "visible") {
        this.refreshOverviewLive();
      }
    };
    document.addEventListener("visibilitychange", this.visibilityChangeHandler);
    this.bootstrap();
    this.startOverviewAutoRefresh();
    this.clockTimer = window.setInterval(() => {
      this.clockNow = new Date();
    }, 1000);
  },
  beforeUnmount() {
    this.stopOverviewAutoRefresh();
    if (this.routeChangeHandler) {
      window.removeEventListener("hashchange", this.routeChangeHandler);
    }
    if (this.visibilityChangeHandler) {
      document.removeEventListener("visibilitychange", this.visibilityChangeHandler);
    }
    if (this.clockTimer) {
      window.clearInterval(this.clockTimer);
    }
  },
}).use(ElementPlus).mount("#app");
