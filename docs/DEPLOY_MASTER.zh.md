# 主控部署说明

这份说明只覆盖 `opengfw-master`。数据库请用户自行准备；首次启动会自动建表和执行迁移。

## 版本要求

- Linux：建议 `amd64` / `arm64`
- Go：`1.26.2`
  依据：[`go.mod`](../go.mod) 里的 `toolchain go1.26.2`
- PostgreSQL：建议 `14+`
  说明：仓库源码没有硬编码最低版本；本文按 PostgreSQL 14+ 编写

## 你需要先准备

- 一台能访问 PostgreSQL 的 Linux 主机
- 一个可用的 PostgreSQL 数据库和账号
- 数据库 DSN
  例子：`postgres://user:pass@127.0.0.1:5432/opengfw?sslmode=disable`

要求：

- 该数据库账号至少要有当前库的建表、建索引、读写权限
- 防火墙放通主控端口
- 如果你打算让主控在线构建 Agent，机器上还需要安装 Go 1.26.2

## 快速部署

### 1. 构建主控

```bash
git clone https://github.com/apernet/OpenGFW.git
cd OpenGFW
./scripts/build-master.sh
```

输出文件默认在：

```text
./dist/opengfw-master
```

### 2. 安装为 systemd 服务

```bash
sudo ./scripts/install-master-service.sh \
  --database-url 'postgres://user:pass@127.0.0.1:5432/opengfw?sslmode=disable' \
  --listen ':9527'
```

默认安装结果：

- 二进制：`/usr/local/bin/opengfw-master`
- 环境文件：`/etc/opengfw/opengfw-master.env`
- systemd 服务：`opengfw-master`
- 工作目录：`/var/lib/opengfw-master`

### 3. 验证

```bash
systemctl status opengfw-master --no-pager
curl http://127.0.0.1:9527/healthz
```

正常返回：

```json
{"status":"ok"}
```

## Docker 部署

如果你更希望直接容器化部署，仓库已经补了：

- Dockerfile：[`docker/master/Dockerfile`](../docker/master/Dockerfile)
- compose 示例：[`docker/compose.master.yml`](../docker/compose.master.yml)
- 环境变量示例：[`docker/master.env.example`](../docker/master.env.example)
- 镜像构建脚本：[`scripts/docker-build-master-image.sh`](../scripts/docker-build-master-image.sh)

### 1. 构建镜像

```bash
git clone https://github.com/apernet/OpenGFW.git
cd OpenGFW
./scripts/docker-build-master-image.sh
```

默认镜像名：

```text
opengfw-master:latest
```

如果要自定义镜像名：

```bash
IMAGE_NAME=registry.example.com/opengfw-master:v0.1 ./scripts/docker-build-master-image.sh
```

### 2. 准备参数

```bash
cp docker/master.env.example docker/master.env
```

编辑 `docker/master.env`，至少改这两项：

```dotenv
OPENGFW_DATABASE_URL=postgres://user:pass@db-host:5432/opengfw?sslmode=disable
OPENGFW_PUBLISH_PORT=9527
```

可选项：

- `OPENGFW_CONTAINER_PORT`
  说明：容器内监听端口，默认 `9527`
- `OPENGFW_EVENT_RETENTION`
- `OPENGFW_METRIC_RETENTION`
- `OPENGFW_RETENTION_INTERVAL`

### 3. 启动容器

```bash
docker compose --env-file docker/master.env -f docker/compose.master.yml up -d
```

### 4. 验证

```bash
docker compose --env-file docker/master.env -f docker/compose.master.yml ps
curl http://127.0.0.1:9527/healthz
```

### 5. 停止

```bash
docker compose --env-file docker/master.env -f docker/compose.master.yml down
```

说明：

- 数据库不在 compose 里，默认认为由用户自行提供
- `OPENGFW_DATABASE_URL` 和服务端口都通过环境变量传入
- 该镜像包含 Go 1.26.2 和项目源码，因此主控内置的 Agent 构建能力可继续使用

## 手工运行

如果你不想用 systemd，可以直接跑：

```bash
OPENGFW_DATABASE_URL='postgres://user:pass@127.0.0.1:5432/opengfw?sslmode=disable' \
./dist/opengfw-master -listen :9527
```

注意：

- 二进制默认监听 `:8080`
- 上面的部署脚本默认使用 `:9527`

## 首次登录

打开：

```text
http://<你的主机IP>:9527/
```

首次进入会看到“初始化管理员”页面，设置管理员账号和密码即可。

## Agent 怎么装

主控起来后，建议直接在 Web UI 里给节点下发安装脚本。

如果你只想手工编译 Agent：

```bash
go build -trimpath -o ./dist/opengfw-agent ./cmd/opengfw-agent
```

当前仓库里 Agent 的默认版本号是：

```text
0.1.0
```

来源：[`cmd/opengfw-agent/main.go`](../cmd/opengfw-agent/main.go)

## 常用运维命令

```bash
systemctl restart opengfw-master
systemctl status opengfw-master --no-pager
journalctl -u opengfw-master -n 100 --no-pager
```

## 最小交付说明

给用户时，最少告知这 4 件事：

1. 需要自备 PostgreSQL 14+，并提供可写 DSN
2. 构建环境是 Go 1.26.2
3. 主控默认部署命令见上面的两条脚本
4. 首次访问 `http://<IP>:9527/` 初始化管理员账号
