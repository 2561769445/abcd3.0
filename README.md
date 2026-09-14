# ABCD 3.0 分布式扫描平台

**月落安全自研**的主控-多节点分布式资产测绘与漏洞扫描平台。

## 3.0 更新(相对 2.0)

- **三阶段扫描(map→ports→deep)**: 测绘语法/域名任务自动起 map 测绘阶段, 测绘大结果分批复用工作队列由全体节点认领 — 不再单机扛回流, 根治单键时代"回流批被本阶段节点抢跑"的结构性竞态
- **资产库升级(dddd-pro 8.8.1)**: 指纹 +134 产品/+634 规则(17692 产品/26514 条), POC +57 条, workflow 映射 +255 产品
- **进度条批内实时化**: map 阶段 live 计数 3 秒一跳, 长批期间进度不再干等跳变
- **四连症状根治**: 日志冻结/资产计数串任务/任务不更新/Hunter 只扫 2 个 — refreshTaskCounters 补 WHERE、pull 任务 ports 阶段跳过测绘(不再烧积分)、进度累加原子化+转段 GETDEL 封顶 100
- **节点纳管自动时间同步**: install.sh 纳管时自动配置 chrony, 防时钟漂移>60s 被主控误判掉线
- **稳定性续修**: ScanPhase 下发缺失(子进程跑全流程)、转段空队列死锁、pull 三键/进度哈希全链清理

## 2.0 曾更新(相对 1.0)

- **pull 拉模式**: 大目标集(>2000 自动切换)逐批入工作队列, 节点拉取式认领 — 肥瘦自动均衡、节点宕机/主控重启任务不断、断点自愈
- **两阶段扫描**: 阶段1 端口+Web探针 → 阶段2 深度(URL批: 目录+指纹+PoC), 全端口大网段不再被单批卡死
- **测绘引擎强化**: Hunter 全局令牌限速(多节点共用 key 不互踩 429)+积分熔断; Fofa/Quake 限流重试; 自动测绘只查域名目标(纯 IP 不烧积分)
- **稳定性大修(14 项)**: 结果入库批量失败降级逐条(毒丸行只丢自己)、HTTP 服务超时+请求体上限、登录失败限速、portmux 协议识别重写(分片/HTTP2/Redis GET)、任务终态统一回收(根除 Redis key 与内存 map 泄漏)、删任务后尾部结果过滤、目标上传超长行容错、进度节流无锁化等
- **真实进度+ETA**: 阶段内细粒度计数, 滑动速率外推剩余时间
- **目标文件上传**: 15 万行目标列表文件直传, 入口双重去重

## 功能

- **分布式集群**: 一条命令纳管任意 Linux 节点(gz 压缩分发, 30 秒上线); 节点级并发(默认 2 任务/节点, 子进程隔离); 任务停止秒杀(进程组级 kill)
- **扫描引擎**: 端口扫描(SYN/TCP)、指纹识别、Nuclei+GoPoc 指纹驱动 PoC(workflow 映射表精准匹配)、弱口令爆破 15+ 协议独立凭据台账、目录爆破、测绘引擎(Hunter/FOFA/Quake, Web 设置页配 key 即配即用+一键验证)
- **🏢 单位收集**: 输入公司名 → 自动转鹰图 `icp.name` 语法(近一年) → 拉备案资产接标准扫描
- **vshell 式节点运维**: Web 交互终端(cd 会话保持/命令历史) + 文件管理(浏览/上传/下载/重命名/删除)
- **数据与报告**: 资产/漏洞(带完整请求响应数据包)/凭据三大台账, 任务聚合展示, HTML/Excel/CSV 导出, 勾选导出/聚合导出
- **通知**: 企业微信/钉钉 webhook(高危漏洞防抖推送+任务完成通知)
- **系统设置**: Webhook/测绘Key/登录密码全部页面内配置, 即改即生效

## 一键部署(全新 Ubuntu/Debian 主控机)

```bash
curl -fsSL https://raw.githubusercontent.com/2561769445/abcd3.0/main/bootstrap.sh | bash
```

自动完成: git/docker(国内阿里源+镜像加速)/go 安装 → 拉源码(直连慢自动切镜像) → 编译 → 起数据库(docker, 含就绪等待) → systemd 服务 → 单端口分流(6379=Web+Redis+纳管) → 打印节点纳管命令。

GitHub 慢的机器: `export GITHUB_PROXY=https://gh-proxy.com/` 后再执行。服务的启动/停止/卸载见下方「服务管理」。

## 节点接入

在任意 Linux 服务器(amd64/arm64) root 执行部署完成时打印的命令:

```bash
curl -s "http://<主控IP>:6379/install.sh?k=<纳管密钥>" | bash
```

自动下载二进制+装 masscan+注册, 重复执行=升级。

## 服务管理

部署完成后一切由 systemd 托管(**开机自启已配好**),日常用 `systemctl` 管理。

### 主控机(3 个服务 + 2 个数据库容器)

```bash
# 启动(开机自启, 手动启动同款)
systemctl start abcd-master abcd-portmux

# 停止(Web/API/调度停止; 节点在跑的任务不受影响——工作队列在 Redis 里,
#   master 停机期间节点继续拉取执行, 结果先积压在队列, master 回来后自动补入库)
systemctl stop abcd-master abcd-portmux

# 重启
systemctl restart abcd-master

# 状态与日志
systemctl status abcd-master
journalctl -u abcd-master -f        # 实时日志
journalctl -u abcd-master -n 50     # 最近 50 行

# 数据库(PG/Redis, master 依赖它们, 一般不用动)
docker stop abcd-pg abcd-redis      # 停(= 任务全部暂停)
docker start abcd-pg abcd-redis     # 起

# 完全停止整套
systemctl stop abcd-master abcd-portmux && docker stop abcd-pg abcd-redis

# 主控完全卸载
systemctl disable --now abcd-master abcd-portmux
docker rm -f abcd-pg abcd-redis
rm -rf /opt/abcd-distributed
```

### 节点机(1 个服务)

```bash
systemctl start abcd-node       # 启动(开机自启)
systemctl stop abcd-node        # 停止(在跑任务被杀; pull 模式未完成工作项回队列由其他节点接管)
systemctl restart abcd-node     # 重启(重复执行 install.sh 也会触发升级+重启)
journalctl -u abcd-node -f      # 实时日志

# 节点一键卸载(停服务+清文件+从主控注销)
curl -s "http://<主控IP>:6379/uninstall.sh?k=<纳管密钥>" | bash
```

### 常见问题

- **改了 service 文件/环境变量**: `systemctl daemon-reload && systemctl restart abcd-master`
- **端口**: 主控 Web/Redis/纳管统一走 6379(portmux 分流); 内部 8080(master)/5433(PG)/6390(Redis) 只绑 127.0.0.1
- **服务起不来**: `journalctl -u abcd-master -n 30` 看最后一行 Fatal 原因

## 修改密码

优先级: **设置页修改 > systemd 环境变量 > 源码默认值**。

**方式〇: 设置页直接改(最简单)** — Web登录 → 系统设置 → 修改登录密码: 即改即生效, 持久化存储重启不丢。

**方式一: 改环境变量(免重编译)** — 编辑 `/etc/systemd/system/abcd-master.service`:

```
ABCD_ADMIN_PASS=你的新密码      # Web登录
ABCD_REDIS_PASS=...            # Redis密码(需与docker redis启动一致)
ABCD_INSTALL_KEY=...           # 节点纳管密钥
ABCD_JWT_SECRET=...            # JWT签名密钥
```

改后 `systemctl daemon-reload && systemctl restart abcd-master`。

**方式二: 改源码** — `master/config.go` 末尾 `LoadConfig()` 里的默认值(如 `"abcd@2026"`)。⚠️ 需同时删掉 service 文件里对应的 `Environment=` 行(否则环境变量覆盖源码), 再重编译部署。

## ⚠️ 安全提醒

- 默认密码(`admin/abcd@2026`、Redis、纳管密钥)仅用于首次启动, 生产环境务必修改(bootstrap 模式下 JWT/纳管密钥已自动随机)
- 6379 端口对外 = Web+Redis+纳管三合一入口, 建议安全组限制来源 IP

## 架构

```
节点 ──纳管/任务/心跳──▶ 6379 portmux ──▶ 8080 master(裸机) ──▶ PG16(docker, 127.0.0.1:5433)
浏览器 ──Web/API──▶ 6379            └──▶ Redis7(docker, 127.0.0.1:6390, 认证)
```

宿主机进程与容器通信一律走 127.0.0.1 端口映射(容器名 DNS 仅容器内生效)。

源码: `cluster/`(协议) `node/`(节点) `master/`(主控+API+前端) `engine/`(扫描引擎) `frontend/`(Vue3, 产物已嵌入无需 node)
