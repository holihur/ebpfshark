# 安装与自动更新

本文档介绍 ebpfshark 的一键安装、systemd 服务、自更新机制和卸载。

## 1. 一键安装

> 如果仓库中没有 `bin/ebpfshark`，安装脚本会从源码构建，需要 eBPF 构建依赖。
> 只想安装现成二进制时使用 `--binary PATH`。

在项目目录中执行：

```bash
cd /root/ebpf
sudo ./install.sh
```

安装脚本会：

1. 使用已有的 `bin/ebpfshark`；没有则自动执行 `make web && make go-build`
   （会先生成 `vmlinux.h` 与 `capture_bpfel.{go,o}`，需要 `clang`、`llvm`、
   `bpftool`、`libbpf-dev`；也可用 `--binary` 安装现成二进制）
2. 安装二进制到 `/usr/local/bin/ebpfshark`
3. 生成 `/etc/ebpfshark/ebpfshark.env`（权限 600）：
   - 管理员用户名 / 随机密码
   - 随机 MCP Bearer Token
   - 监听地址 `:9999`
   - 自动更新配置
4. 写入 systemd 服务 `/etc/systemd/system/ebpfshark.service`
5. `systemctl enable --now ebpfshark`
6. 在终端打印登录凭据、MCP Token 和更新配置

安装完成后访问：

```text
http://<服务器IP>:9999
```

如果服务器有防火墙，请放行端口（默认 9999），例如：

```bash
ufw allow 9999/tcp
```

> 服务默认监听所有网卡且没有 TLS。公网部署请使用 HTTPS 反向代理并限制来源 IP。

### 常用参数

```bash
sudo ./install.sh \
  --port 9999 \
  --auth-user admin \
  --auth-pass 'change-this-password' \
  --mcp-token 'change-this-mcp-token' \
  --update-url 'https://example.com/ebpfshark/manifest.json' \
  --update-interval 10m
```

| 参数 | 说明 |
| --- | --- |
| `--port` | HTTP/Web 端口，默认 9999 |
| `--binary PATH` | 安装指定二进制，不重新构建 |
| `--rebuild` | 强制 `make web && make go-build` |
| `--auth-user` / `--auth-pass` | 首次安装的登录凭据 |
| `--mcp-token` | MCP HTTP Bearer Token |
| `--update-url` | 自动更新 manifest 地址 |
| `--update-interval` | 检查间隔，默认 `10m` |
| `--no-auto-update` | 关闭自动更新 |
| `--force-env` | 重新生成 env 文件（会覆盖现有密码/Token） |
| `--no-systemd` | 只安装文件，不操作 systemd |
| `--prefix DIR` | 安装到指定根目录（测试用，隐含 `--no-systemd`） |
| `--uninstall` | 停止并卸载服务和二进制 |
| `--purge` | 与 `--uninstall` 一起删除 env 文件 |

重复执行安装脚本时，默认**保留已有 env 文件**（密码和 Token 不变）。需要轮换凭据时：

```bash
sudo ./install.sh --force-env --auth-pass 'new-password' --mcp-token 'new-token'
```

### 手动安装（不使用 systemd）

```bash
sudo install -D -m 0755 bin/ebpfshark /usr/local/bin/ebpfshark
sudo mkdir -p /etc/ebpfshark
sudo tee /etc/ebpfshark/ebpfshark.env >/dev/null <<'EOF'
EBPFSHARK_ADDR=":9999"
EBPFSHARK_AUTH_USER="admin"
EBPFSHARK_AUTH_PASS="change-this-password"
EBPFSHARK_MCP_TOKEN="change-this-mcp-token"
EBPFSHARK_AUTO_UPDATE="true"
EBPFSHARK_UPDATE_INTERVAL="10m"
EBPFSHARK_UPDATE_URL="https://example.com/ebpfshark/manifest.json"
EOF
sudo chmod 600 /etc/ebpfshark/ebpfshark.env

sudo set -a; . /etc/ebpfshark/ebpfshark.env; set +a
sudo -E /usr/local/bin/ebpfshark
```

## 2. systemd 服务

```bash
systemctl status ebpfshark
systemctl restart ebpfshark
journalctl -u ebpfshark -f
```

服务单元关键配置：

```ini
[Service]
EnvironmentFile=/etc/ebpfshark/ebpfshark.env
ExecStart=/usr/local/bin/ebpfshark
Restart=always
RestartSec=3
LimitMEMLOCK=infinity
```

- 服务以 root 运行：eBPF TCX 挂载需要 `CAP_BPF` / `CAP_NET_ADMIN`，自更新需要写
  `/usr/local/bin`。
- 不需要手动传 `-addr` / `-auth-pass`，全部通过 env 文件注入。
- 修改 env 后执行 `systemctl restart ebpfshark` 生效。

## 3. 自动更新

### 3.1 默认行为

| 配置 | 默认值 |
| --- | --- |
| 启用 | 是（`EBPFSHARK_AUTO_UPDATE=true`） |
| 检查间隔 | 10 分钟（`EBPFSHARK_UPDATE_INTERVAL=10m`） |
| 首次检查 | 启动后约 30 秒 |
| Manifest | 空（未配置时不会下载任何内容） |

**自动更新需要配置 manifest URL**（`--update-url` 或 `EBPFSHARK_UPDATE_URL`）。未配置时
服务仍正常运行，只在日志中提示自动更新处于 idle 状态。

### 3.2 更新流程

1. 每隔 `EBPFSHARK_UPDATE_INTERVAL` 拉取 manifest
2. 用 semver 比较版本（当前版本由编译时 `-ldflags` 注入，默认 `0.1.0-dev`）
3. 发现新版本后下载二进制
4. 校验必须提供的 SHA-256
5. 校验文件是 Linux ELF
6. 写入同目录临时文件 → `rename` 原子替换
7. 重新执行新二进制（`syscall.Exec`，进程 PID 保持不变）

安全限制：

- Manifest 和下载地址必须使用 **HTTPS**（仅 `127.0.0.1` / `localhost` 允许 HTTP，便于测试）
- `sha256` 必须为 64 位十六进制字符串，校验失败不会替换
- 下载大小上限 256 MiB
- 抓包正在运行时跳过本次更新，等待下一个周期，避免中断抓包
- 更新后所有内存状态重置：登录会话失效、抓包停止、缓冲区清空

### 3.3 Manifest 格式

```json
{
  "version": "0.2.0",
  "url": "https://example.com/ebpfshark/ebpfshark-linux-amd64",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "notes": "optional release notes"
}
```

- `version`：semver，`0.2.0` 或 `v0.2.0` 均可
- `url`：可以是绝对 URL，也可以相对 manifest 地址
- `sha256`：更新二进制的 SHA-256（必填）

生成本地 manifest 示例：

```bash
cd /root/ebpf
make web && make go-build
cp bin/ebpfshark /srv/ebpfshark/ebpfshark-linux-amd64
SHA=$(sha256sum /srv/ebpfshark/ebpfshark-linux-amd64 | awk '{print $1}')
cat > /srv/ebpfshark/manifest.json <<EOF
{
  "version": "0.2.0",
  "url": "ebpfshark-linux-amd64",
  "sha256": "$SHA"
}
EOF
```

用 HTTPS 静态服务器托管该目录（Nginx、Caddy、GitHub Releases 等均可），然后把
`https://your-host/manifest.json` 配置到 `EBPFSHARK_UPDATE_URL`。

> `make go-build` 通过 `VERSION` 变量写入版本号：
> `make go-build VERSION=0.2.0`。请保证 manifest 的 version 与二进制一致。

### 3.4 关闭 / 调整

关闭自动更新：

```bash
sudo sed -i 's/^EBPFSHARK_AUTO_UPDATE=.*/EBPFSHARK_AUTO_UPDATE="false"/' \
  /etc/ebpfshark/ebpfshark.env
sudo systemctl restart ebpfshark
```

或安装时：

```bash
sudo ./install.sh --no-auto-update
```

调整间隔：

```bash
sudo sed -i 's/^EBPFSHARK_UPDATE_INTERVAL=.*/EBPFSHARK_UPDATE_INTERVAL="30m"/' \
  /etc/ebpfshark/ebpfshark.env
sudo systemctl restart ebpfshark
```

运行时命令行参数（优先级高于 env）：

```bash
ebpfshark -auto-update=false -update-interval 30m -update-url https://...
```

### 3.5 查看更新状态

受保护的 API：

```bash
# 先登录获取 Cookie
curl -s -c /tmp/ebpf.cookie -X POST localhost:9999/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<password>"}'

curl -s -b /tmp/ebpf.cookie localhost:9999/api/update | jq
```

返回示例：

```json
{
  "enabled": true,
  "manifestUrl": "https://example.com/manifest.json",
  "currentVersion": "0.1.0-dev",
  "intervalSeconds": 600,
  "lastCheck": "2026-10-21T12:00:00Z",
  "lastResult": "up to date",
  "latestVersion": "0.2.0",
  "updateAvailable": false
}
```

日志：

```bash
journalctl -u ebpfshark -f | grep -i update
```

## 4. 卸载

```bash
# 停止并删除服务与二进制，保留配置
sudo ./install.sh --uninstall

# 同时删除 env（包含密码与 Token）
sudo ./install.sh --uninstall --purge
```

## 5. 安全建议

1. `/etc/ebpfshark/ebpfshark.env` 包含登录密码和 MCP Token，保持 600 权限，勿提交仓库。
2. 自动更新只校验 SHA-256，不验证 GPG/Minisign 签名；manifest 托管账号被攻破会导致
   任意二进制替换。高安全环境请关闭自动更新（`--no-auto-update`）并手动升级。
3. 公网访问请使用 HTTPS 反向代理；服务本身不终止 TLS。
4. 升级前建议备份当前二进制：
   ```bash
   sudo cp /usr/local/bin/ebpfshark /usr/local/bin/ebpfshark.bak
   ```
5. 自动更新会中断抓包并清空内存缓冲（登录会话也会失效），请选择低峰期或在
   `EBPFSHARK_UPDATE_INTERVAL` 中设置较大间隔。
6. 服务以 root 运行。若需降权，可改用专用用户 + `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN`
   并确保该用户对二进制有写权限（自动更新需要）。

## 6. 故障排查

| 现象 | 处理 |
| --- | --- |
| 服务启动失败 | `journalctl -u ebpfshark -n 100 --no-pager` |
| 端口占用 | `ss -ltnp \| grep 9999`，修改 `EBPFSHARK_ADDR` 后重启 |
| 无法抓包 | 确认服务以 root 运行，内核 ≥ 6.6 且存在 `/sys/kernel/btf/vmlinux` |
| 自动更新没有动作 | 检查 `EBPFSHARK_UPDATE_URL` 是否配置、HTTPS、manifest 是否可访问 |
| 更新后仍是旧版本 | 确认 manifest.version 大于当前版本，检查日志中的 checksum/ELF 错误 |
| 更新后登录失效 | 正常现象：会话保存在内存中，更新重启后需重新登录 |
| 需要回滚 | 用备份的 `/usr/local/bin/ebpfshark.bak` 覆盖并重启 |
