package node

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"abcd/cluster"
	"abcd/common"
	"abcd/common/uncover"
	"abcd/ddout"
	"abcd/engine"
	"abcd/structs"
	"abcd/utils"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

var (
	currentTaskID    atomic.Value // string
	currentCancel    atomic.Value // context.CancelFunc
	runningFlag      atomic.Bool
	progressCounters atomic.Int64   // 已上报结果条数
	runningSet       = sync.Map{}   // taskID -> struct{}{} 在跑任务集合(并发模式心跳聚合)
	childCancels     = sync.Map{}   // taskID -> context.CancelFunc 并发子进程取消器
)

// ExecRun -node-exec 子进程入口: 读任务JSON跑单任务退出(与父节点进程全局状态隔离)
func ExecRun(args []string) {
	if len(args) < 1 {
		os.Exit(2)
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		os.Exit(3)
	}
	var task cluster.Task
	if err := json.Unmarshal(b, &task); err != nil {
		os.Exit(4)
	}
	opt.nodeID = os.Getenv("ABCD_NODE_ID")
	opt.nodeName = opt.nodeID
	db := 0
	if v := os.Getenv("ABCD_EXEC_REDIS_DB"); v != "" {
		db, _ = strconv.Atoi(v)
	}
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("ABCD_EXEC_REDIS_ADDR"),
		Password: os.Getenv("ABCD_EXEC_REDIS_PASS"),
		DB:       db,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		os.Exit(5)
	}
	// Hunter全局令牌限速: 子进程同样注入(每公司一个子进程, 都要过令牌)
	uncover.SetHunterRedis(rdb)
	// pull模式子进程: 静默执行单个工作项, 不写task:state/task:progress(父拉取循环统一管)
	if os.Getenv("ABCD_PULL_CHILD") == "1" {
		silentTask(ctx, &task)
		return
	}
	runTask(ctx, &task)
}

// silentTask pull子任务执行: 跑引擎但不setTaskState(父循环按INCR计数推进度)
func silentTask(ctx context.Context, task *cluster.Task) {
	start := time.Now()
	err := executeScan(ctx, task)
	status := "ok"
	if ctx.Err() != nil {
		status = "stopped"
	} else if err != nil {
		status = "failed"
	}
	gologger.Info().Msgf("pull子任务结束: %s %s err=%v 耗时=%s", task.ID, status, err, time.Since(start))
	// 失败也要INCR(工作项已被消费, 不重试避免毒丸循环; 失败信息走日志)
}

// execChild 并发模式: fork子进程跑任务, 全局状态进程级隔离
// pullWork非空时: 子进程静默跑单个工作项(ABCD_PULL_CHILD=1), 完成后INCR拉取计数
func execChild(pctx context.Context, task *cluster.Task, pullWork string) {
	// pull工作项: 复制描述子任务, Targets换成工作项内容
	// pullWork为换行分隔批量串(每批N个目标, 大列表场景进程开销摊薄N倍);
	// 旧队列存量批次是逗号分隔 — URL目标含逗号会被切坏, 故新批次一律换行
	if pullWork != "" {
		t := *task
		t.Targets = splitWorkItem(pullWork)
		task = &t
	}
	raw, _ := json.Marshal(task)
	// 文件名带PID+纳秒: 同一任务重复派发时并发子进程互不覆写
	tmp := filepath.Join(os.TempDir(), fmt.Sprintf("abcd-task-%s-%d-%d.json",
		strings.ReplaceAll(task.ID, ":", "_"), os.Getpid(), time.Now().UnixNano()))
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		gologger.Error().Msgf("任务文件写入失败: %v", err)
		return
	}
	defer os.Remove(tmp)

	cctx, cancel := context.WithCancel(pctx)
	defer cancel() // 正常完成路径也要释放: 否则kill-waiter goroutine按任务数泄漏
	childCancels.Store(task.ID, cancel)
	defer childCancels.Delete(task.ID)
	runningSet.Store(task.ID, struct{}{})
	defer runningSet.Delete(task.ID)

	gologger.Info().Msgf("子进程执行: %s (%s) 目标数=%d", task.ID, task.Name, len(task.Targets))
	exe, _ := os.Executable()
	cmd := exec.CommandContext(cctx, exe, "-node-exec", tmp)
	setPgid(cmd) // 独立进程组: kill连masscan孙进程一起收
	// ctx取消(停止/超时)时升级为组杀, 秒停引擎任意阶段
	go func() {
		<-cctx.Done()
		killGroup(cmd)
	}()
	cmd.Env = append(os.Environ(),
		"ABCD_NODE_ID="+opt.nodeID,
		"ABCD_EXEC_REDIS_ADDR="+opt.redisAddr,
		"ABCD_EXEC_REDIS_PASS="+opt.redisPass,
		"ABCD_EXEC_REDIS_DB="+strconv.Itoa(opt.redisDB))
	if pullWork != "" {
		cmd.Env = append(cmd.Env, "ABCD_PULL_CHILD=1")
	}
	cmd.Stdout = os.Stdout // 子进程日志透传到journalctl
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if cctx.Err() != nil {
		// 被stop指令/父退出kill: 补终态(子进程可能没来得及上报)
		if pullWork == "" {
			setTaskState(task.ID, "stopped", "killed")
		}
	}
	if pullWork != "" {
		// 计数唯一落点=父进程按工作项(批) — 父子两边都INCR会导致done双计(可到900%)
		// live对冲由master统一做(done跳增N时补扣live N): 单一对冲路径, 节点热替换零依赖
		cctx2, cc2 := context.WithTimeout(context.Background(), 5*time.Second)
		defer cc2()
		rdb.IncrBy(cctx2, cluster.PullDonePrefix+task.ID, int64(len(splitWorkItem(pullWork))))
	}
	gologger.Info().Msgf("子进程结束: %s err=%v", task.ID, err)
}

// splitWorkItem 拆工作项批次为新旧两代格式兼容: 新批次换行分隔(URL含逗号不被切坏),
// 存量队列里的旧逗号批次按逗号拆
func splitWorkItem(work string) []string {
	if strings.Contains(work, "\n") {
		return strings.Split(work, "\n")
	}
	return strings.Split(work, ",")
}

// runPullLoop pull模式拉取循环: BRPopLPush工作项(原子转入本节点在途队列) → 子进程执行
// → 计数 → LRem在途 → 循环直到队列空。多节点同抢一个队列, 谁空闲谁领得多;
// 中途stop=kill子进程+剩余工作项留队列(master可重推);
// 节点崩溃时在途项留在pullproc队列, master回收搬回公共队列(100%不丢)。
// v69: 循环由taskLoop按并发槽goroutine化 — 单节点可并行多个pull任务(每任务占1槽),
// 本函数自身逻辑不变(循环内子进程仍串行, 每时刻1个子进程)。
// 注: BRPopLPush从队尾弹(与旧版BLPop队头弹混布兼容), 批次间无依赖, 顺序无关。
func runPullLoop(ctx context.Context, task *cluster.Task) {
	qkey := cluster.QueuePullKey(task.ID, task.Options.ScanPhase)
	procKey := cluster.QueuePullProcKey(opt.nodeID, task.ID, task.Options.ScanPhase)
	// 心跳标记正在跑pull任务(running_task= pull:{taskID}:{phase}, master前缀Contains判定兼容)。
	// 键带phase且与taskLoop的LoadOrStore防重登记同键: 多pull循环并行后, 其他循环的
	// 收工Delete不会误删本条目(master判活/防提前done全靠它)
	hbKey := "pull:" + task.ID + ":" + task.Options.ScanPhase
	runningSet.Store(hbKey, struct{}{}) // 幂等: taskLoop领描述子时已LoadOrStore登记
	defer runningSet.Delete(hbKey)

	gologger.Info().Msgf("进入pull循环: %s 队列=%s", task.ID, qkey)
	idle := 0 // 连续空手次数: 描述子可能先于master灌工作项到达, 要容忍前几个10s空窗
	for {
		select {
		case <-ctx.Done():
			gologger.Info().Msgf("pull循环退出(停止): %s", task.ID)
			return
		default:
		}
		// 10s超时阻塞领取, 原子弹入在途队列: 空手累计3次(30s)才收工 — 防描述子先到/工作项未灌完的时序误判
		work, err := rdb.BRPopLPush(ctx, qkey, procKey, 10*time.Second).Result()
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				idle++
				if idle >= 3 {
					gologger.Info().Msgf("pull队列已空(连续%d次空手), 收工: %s", idle, task.ID)
					return
				}
				continue
			}
			gologger.Warning().Msgf("pull领取异常: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		idle = 0
		gologger.Info().Msgf("pull领取: %s <- %s", task.ID, work)
		execChild(ctx, task, work)
		// 批次收尾(完成/被杀都算): 从在途队列移除。值=work原始串, 与BRPopLPush
		// 入队的元素完全一致, 精确匹配。重试3次: 高负载节点(portmux/双任务叠跑)LRem
		// 可能超时静默失败, 残留由master的procPendingFor安全阀兜底清(节点收工=批次已计done)
		for i := 0; i < 3; i++ {
			rctx, rc := context.WithTimeout(context.Background(), 15*time.Second)
			err := rdb.LRem(rctx, procKey, 0, work).Err()
			rc()
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
	}
}

// selfHealInflight 节点启动自愈: 上次进程崩溃/重启时留在pullproc键里的在途项,
// 先于任何领取动作搬回公共队列(master回收也覆盖此场景, 但自己搬零延迟;
// 双方并发搬最坏=同批被扫两遍, 资产唯一键挡重复, done计数封顶, 无害)
func selfHealInflight(ctx context.Context) {
	iter := rdb.Scan(ctx, 0, cluster.QueuePullProcPrefix+opt.nodeID+":*", 100).Iterator()
	for iter.Next(ctx) {
		procKey := iter.Val()
		// 键=queue:pullproc:{nodeID}:{taskID}[:{phase}] → 解析路由
		parts := strings.Split(strings.TrimPrefix(procKey, cluster.QueuePullProcPrefix), ":")
		if len(parts) < 2 || parts[1] == "" {
			rdb.Del(ctx, procKey) // 解析不出taskID的脏键直接清
			continue
		}
		taskID, phase := parts[1], ""
		if len(parts) >= 3 {
			phase = parts[2]
		}
		items, err := rdb.LRange(ctx, procKey, 0, -1).Result()
		if err != nil || len(items) == 0 {
			rdb.Del(ctx, procKey)
			continue
		}
		vals := make([]interface{}, len(items))
		for i, v := range items {
			vals[i] = v
		}
		if rdb.RPush(ctx, cluster.QueuePullKey(taskID, phase), vals...).Err() == nil {
			rdb.Del(ctx, procKey)
			gologger.Info().Msgf("节点重启自愈: %s 搬回%d项 -> %s", taskID, len(items), cluster.QueuePullKey(taskID, phase))
		}
	}
}

func cancelCurrentTask() {
	if f, ok := currentCancel.Load().(context.CancelFunc); ok && f != nil {
		f()
	}
}

func runTask(parent context.Context, task *cluster.Task) {
	if runningFlag.Load() {
		// 不应发生(串行), 防御
		gologger.Error().Msg("任务冲突: 上一任务未结束")
		return
	}
	runningFlag.Store(true)
	defer runningFlag.Store(false)
	progressCounters.Store(0) // 每个任务重置进度计数
	runningSet.Store(task.ID, struct{}{})
	defer runningSet.Delete(task.ID)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	currentTaskID.Store(task.ID)
	currentCancel.Store(cancel)
	defer currentCancel.Store(context.CancelFunc(nil))
	defer currentTaskID.Store("") // 清残留: done后心跳running_task不再挂旧ID

	setTaskState(task.ID, "scanning", "")
	start := time.Now()

	err := executeScan(ctx, task)

	status := "done"
	if ctx.Err() != nil || err == context.Canceled {
		status = "stopped"
	} else if err != nil {
		status = "failed"
	}
	setTaskState(task.ID, status, time.Since(start).String())
	gologger.Info().Msgf("任务结束: %s status=%s 耗时=%s", task.ID, status, time.Since(start))
}

// executeScan 填GlobalConfig→初始化→跑扫描, hook实时上报结果
func executeScan(ctx context.Context, task *cluster.Task) error {
	// 阶段hook: 上报扫描阶段进度
	engine.SetStageHook(func(stage string) {
		pct := engine.StagePct(stage)
		if pct < 0 {
			return
		}
		cctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
		defer cc()
		rdb.HSet(cctx, cluster.ProgressPrefix+task.ID, map[string]interface{}{
			"stage":     stage,
			"stage_cn":  engine.StageCN(stage),
			"progress":  pct,
			"update_ts": time.Now().Unix(),
		})
	})

	// 细粒度进度hook: 阶段内done/total计数(5s节流, masscan每host回调很密) → master算真实百分比+ETA。
	// hook在引擎多个goroutine里并发调用, 节流戳必须atomic
	var lastProgressWrite atomic.Int64
	engine.SetProgressHook(func(stage string, done, total int64) {
		now := time.Now().Unix()
		for { // CAS抢写窗口: 只有一个并发调用能通过
			prev := lastProgressWrite.Load()
			if now-prev < 5 {
				return
			}
			if lastProgressWrite.CompareAndSwap(prev, now) {
				break
			}
		}
		pct := int64(0)
		if total > 0 {
			pct = done * 100 / total
		}
		cctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
		defer cc()
		rdb.HSet(cctx, cluster.ProgressPrefix+task.ID, map[string]interface{}{
			"stage":      stage,
			"stage_cn":   engine.StageCN(stage) + fmt.Sprintf(" %d/%d", done, total),
			"progress":   pct,
			"done_count": done,
			"total_count": total,
			"update_ts":  now,
		})
	})

	// 批内实时进度hook: pull子进程每查完一个关键词INCR live计数,
	// 前端进度条按查询粒度(≈3s一跳)动, 不再整批(25个目标)跳变;
	// 整批完成时父进程DecrBy对冲(execChild), 防done+live双计
	if os.Getenv("ABCD_PULL_CHILD") == "1" {
		uncover.HunterProgressHook = func() {
			cctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
			defer cc()
			rdb.Incr(cctx, cluster.PullLivePrefix+task.ID)
			rdb.Expire(cctx, cluster.PullLivePrefix+task.ID, 24*time.Hour)
		}
		defer func() { uncover.HunterProgressHook = nil }()
	}

	// 结果hook: 每条结果包信封LPUSH到结果队列
	// 阶段产物回流: map阶段收集测绘资产(→ports工作项), ports阶段收集活URL(→deep工作项);
	// 子进程结束时灌回本任务pull队列, 由全部节点认领 — 测绘/扫描的重活不再单机扛
	var mu sync.Mutex
	phase2URLs := make([]string, 0, 1024)
	var phase2Capped atomic.Bool // 截断只告警一次, 不逐条刷日志
	ddout.SetOutputHook(func(o ddout.OutputMessage) {
		progressCounters.Add(1)
		collect := ""
		if task.Options.ScanPhase == "map" && o.Type == "MapAsset" && o.URI != "" {
			collect = o.URI
		} else if task.Options.ScanPhase == "ports" && o.Type == "Web" && o.URI != "" {
			collect = o.URI
		}
		if collect != "" {
			mu.Lock()
			if len(phase2URLs) < 200000 { // 防极端爆量
				phase2URLs = append(phase2URLs, collect)
			} else if phase2Capped.CompareAndSwap(false, true) {
				gologger.Warning().Msgf("阶段产物收集达20万上限, 超出部分不再回流: %s", task.ID)
			}
			mu.Unlock()
		}
		raw, err := o.ToJson()
		if err != nil {
			return
		}
		env := cluster.ResultEnvelope{
			TaskID: task.ID,
			NodeID: opt.nodeID,
			Msg:    json.RawMessage(raw),
		}
		b, _ := json.Marshal(env)
		// 带短超时, 不阻塞扫描主流程; 失败重试一次
		cctx, cc := context.WithTimeout(ctx, 5*time.Second)
		defer cc()
		if err := rdb.LPush(cctx, cluster.QueueResults, string(b)).Err(); err != nil {
			_ = rdb.LPush(context.Background(), cluster.QueueResults, string(b)).Err()
		}
	})
	defer ddout.SetOutputHook(nil)

	// 填GlobalConfig
	o := task.Options
	cfg := &structs.GlobalConfig
	*cfg = structs.Config{} // 清零, 防上一任务残留
	cfg.ScanPhase = o.ScanPhase // 阶段开关必须下发引擎(漏了=子进程永远跑全流程, v56起祖传遗漏)
	cfg.Mode = o.Mode           // pull模式ports阶段跳过测绘: 工作项是资产URL/IP批, 再跑测绘=浪费
	cfg.Targets = append(cfg.Targets, task.Targets...)
	cfg.Ports = task.Ports
	cfg.PortScanType = o.PortScanType
	if cfg.PortScanType == "" {
		cfg.PortScanType = "syn" // 默认SYN, 无masscan自动降级TCP
	}
	cfg.TCPPortScanThreads = o.TCPPortScanThreads
	cfg.WebThreads = o.WebThreads
	cfg.WebTimeout = o.WebTimeout
	// 线程/超时默认值(与命令行flag默认一致)
	if cfg.TCPPortScanThreads <= 0 {
		cfg.TCPPortScanThreads = 1000
	}
	if cfg.SYNPortScanThreads <= 0 {
		cfg.SYNPortScanThreads = 20000 // masscan rate: 实测50k丢包反而漏(89<128条), 20k+retries2为该带宽最优
	}
	if cfg.WebThreads <= 0 {
		cfg.WebThreads = 200
	}
	if cfg.WebTimeout <= 0 {
		cfg.WebTimeout = 10
	}
	if cfg.GetBannerThreads <= 0 {
		cfg.GetBannerThreads = 500
	}
	if cfg.GetBannerTimeout <= 0 {
		cfg.GetBannerTimeout = 5
	}
	if cfg.TCPPortScanTimeout <= 0 {
		cfg.TCPPortScanTimeout = 6
	}
	if cfg.PortsThreshold <= 0 {
		cfg.PortsThreshold = 300
	}
	if cfg.SubdomainBruteForceThreads <= 0 {
		cfg.SubdomainBruteForceThreads = 600 // dnsx多resolver分摊, 150太保守
	}
	if cfg.GoPocThreads <= 0 {
		cfg.GoPocThreads = 50
	}
	cfg.NoPoc = o.NoPoc
	cfg.NoGolangPoc = o.NoGolangPoc
	cfg.DisableGeneralPoc = o.DisableGeneralPoc
	cfg.PocNameForSearch = o.PocNameForSearch
	cfg.NoDirSearch = o.NoDirSearch
	cfg.NoServiceBruteForce = o.NoServiceBrute
	cfg.Subdomain = o.Subdomain
	cfg.NoSubdomainBruteForce = o.NoSubdomainBruteForce
	cfg.NoSubFinder = o.NoSubFinder
	cfg.AllowLocalAreaDomain = o.AllowLocalAreaDomain
	cfg.AllowCDNAssets = o.AllowCDNAssets
	cfg.NoHostBind = o.NoHostBind
	cfg.NoICMPPing = o.NoICMPPing
	cfg.TCPPing = o.TCPPing
	cfg.SkipHostDiscovery = o.SkipHostDiscovery
	cfg.NoPortString = o.NoPortString
	cfg.MasscanPath = o.MasscanPath
	if cfg.MasscanPath == "" {
		cfg.MasscanPath = "masscan"
	}
	cfg.AdaptiveTCPScan = o.AdaptiveTCP
	cfg.Hunter = o.Hunter
	cfg.Fofa = o.Fofa
	cfg.Quake = o.Quake
	cfg.HunterPageSize = o.HunterPageSize
	cfg.HunterMaxPageCount = o.HunterMaxPage
	cfg.FofaMaxCount = o.FofaMaxCount
	cfg.QuakeSize = o.QuakeSize
	// 测绘分页默认值兜底: 不传(0)时翻页循环一次都不跑, Hunter拉0条
	if cfg.HunterPageSize <= 0 {
		cfg.HunterPageSize = 10 // 个人账号page_size过大会429限流, 10为安全值(VIP可在任务里调大)
	}
	if cfg.HunterMaxPageCount <= 0 {
		cfg.HunterMaxPageCount = 50 // ps=10: 默认拉前500条0 // page_size=10: 50页=默认拉前500条资产
	}
	if cfg.FofaMaxCount <= 0 {
		cfg.FofaMaxCount = 500 // extended账号单次500实测OK
	}
	if cfg.QuakeSize <= 0 {
		cfg.QuakeSize = 500 // quake实测size=500正常
	}
	cfg.LowPerceptionMode = o.LowPerception
	cfg.OnlyIPPort = o.OnlyIPPort
	cfg.Severities = o.Severities
	cfg.ExcludeTags = o.ExcludeTags
	cfg.NoInteractsh = o.NoInteractsh
	cfg.InteractshURL = o.InteractshURL
	cfg.InteractshToken = o.InteractshToken
	cfg.HTTPProxy = o.HTTPProxy
	cfg.HTTPProxyTest = false
	cfg.Password = o.Password
	cfg.PasswordFile = o.PasswordFile
	cfg.Xray = o.Xray
	cfg.Xscan = o.Xscan
	cfg.OssBucket = o.Oss
	cfg.Findre = o.Findre
	cfg.JSAPIScan = o.JSAPIScan
	// 节点模式不落本地文件/不生成HTML报告
	cfg.OutputFile = ""
	cfg.OutputType = "text"
	cfg.ReportName = ""
	cfg.NoBanner = true
	// prepare()依赖的默认路径
	cfg.APIConfigFilePath = "config/api-config.yaml"

	// 拉取主控设置页配置的测绘key → 覆盖本地api-config.yaml(即配即用, 全节点生效)
	if yml, err := rdb.Get(ctx, "cluster:apiconfig").Result(); err == nil && strings.TrimSpace(yml) != "" {
		_ = os.MkdirAll("config", 0755)
		_ = os.WriteFile(cfg.APIConfigFilePath, []byte(yml), 0644)
	}
	// 域名目标自动开测绘收集: 全端口/标准扫描砍掉子域爆破后, 用测绘引擎补子域与资产
	// v49: 仅提取域名目标去查测绘(纯IP/CIDR不进测绘队列) — 之前把9588个IP逐个查Hunter,
	//      每个IP一查就是500条积分, 近万目标直接烧光当日配额(2026-09-01全端口任务事故)
	if !cfg.Hunter && !cfg.Fofa && !cfg.Quake {
		engines := availableMapEngines()
		if task.Options.ScanPhase == "map" && len(engines) > 0 {
			// v70 引擎分流: 语法查询串(icp.name=公司名等)只有Hunter完整支持→Hunter独跑;
			// 普通目标(域名/IP)→Fofa+Quake并行 — Hunter不再参与域名测绘:
			// ①3s全局限速闸被域名查询占满会拖慢语法批 ②翻页大户烧Hunter积分
			// ③fofa/quake各自独立限速, 并行后吞吐翻倍。
			// 混批(语法+普通, master分桶前的存量)整体走Hunter保底不丢目标;
			// fofa/quake都无key时降级Hunter。
			hasHunter := false
			for _, e := range engines {
				if e == "hunter" {
					hasHunter = true
				}
			}
			if hasHunter && batchHasSyntax(task.Targets) {
				cfg.Hunter = true
			} else {
				for _, e := range engines {
					if e == "fofa" {
						cfg.Fofa = true
					} else if e == "quake" {
						cfg.Quake = true
					}
				}
				if !cfg.Fofa && !cfg.Quake && hasHunter {
					cfg.Hunter = true // fofa/quake都没key: 降级
				}
			}
		} else if hasDomainTarget(task.Targets) && len(engines) > 0 {
			// 只把域名类目标送进测绘; IP/CIDR/IP段保持原样走端口扫描
			var domainOnly []string
			for _, t := range task.Targets {
				if utils.GetInputType(t) == structs.TypeDomain || utils.GetInputType(t) == structs.TypeDomainPort {
					domainOnly = append(domainOnly, t)
				}
			}
			if len(domainOnly) > 0 {
				for _, e := range engines {
					if e == "hunter" {
						cfg.Hunter = true
					} else if e == "fofa" {
						cfg.Fofa = true
					} else if e == "quake" {
						cfg.Quake = true
					}
				}
				task.Targets = domainOnly
				gologger.Info().Msgf("检测到域名目标且测绘key已配置: 自动开启%s, 仅测绘%d个域名目标(IP目标跳过测绘直扫端口)",
					strings.Join(engines, "+"), len(domainOnly))
			}
		}
	}
	cfg.NucleiTemplate = "config/pocs"
	cfg.WorkflowYamlPath = "config/workflow.yaml"
	cfg.FingerConfigFilePath = "config/finger.yaml"
	cfg.DirSearchYaml = "config/dir.yaml"
	cfg.SubdomainWordListFile = "config/subdomains.txt"

	common.SetTargetString(joinTargets(task.Targets))
	common.SetPortString(task.Ports)

	// 初始化(指纹库/hmap等)
	common.InitPrepare()

	err := engine.RunScan(ctx)

	// 阶段跑完 → 收集到的产物(map=测绘资产 / ports=活URL)按批灌回本任务pull队列(下一阶段工作项)。
	// 任务被停止(ctx取消)时不灌 — 防半截产物复活进已删队列成僵尸
	if ctx.Err() == nil && (task.Options.ScanPhase == "ports" || task.Options.ScanPhase == "map") && len(phase2URLs) > 0 {
		mu.Lock()
		urls := phase2URLs
		phase2URLs = nil
		mu.Unlock()
		fctx, fc := context.WithTimeout(context.Background(), 30*time.Second)
		defer fc()
		// 回流目标: 下一阶段的独立队列键(map→ports, ports→deep) —
		// 本阶段拉取循环只认自己的键, 回流批由转段后的新循环认领
		next := "deep"
		if task.Options.ScanPhase == "map" {
			next = "ports"
		}
		batch := 25
		items := make([]interface{}, 0, len(urls)/batch+1)
		for i := 0; i < len(urls); i += batch {
			end := i + batch
			if end > len(urls) {
				end = len(urls)
			}
			items = append(items, strings.Join(urls[i:end], "\n"))
		}
		if err2 := rdb.RPush(fctx, cluster.QueuePullKey(task.ID, next), items...).Err(); err2 != nil {
			gologger.Error().Msgf("阶段产物入队失败: %v", err2)
		} else {
			// 产物总数写给master转段用(total=条数而非批数, 下一阶段进度单位一致)。
			// INCRBY累加而非SET: 多个子进程先后回流, SET会被最后一个覆盖成部分值(进度>100%假象)
			rdb.IncrBy(fctx, "task:pull:phase2total:"+task.ID, int64(len(urls)))
			rdb.Expire(fctx, "task:pull:phase2total:"+task.ID, 24*time.Hour)
			gologger.Info().Msgf("阶段(%s)产出 %d 条资产已回流浪队列(%d批)", task.Options.ScanPhase, len(urls), len(items))
		}
	}
	return err
}

func setTaskState(taskID, status, extra string) {
	ctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
	defer cc()
	rdb.Set(ctx, cluster.TaskStatePrefix+taskID, status+"|"+extra, 24*time.Hour)
	rdb.HSet(ctx, cluster.ProgressPrefix+taskID, map[string]interface{}{
		"status":    status,
		"node":      opt.nodeID,
		"results":   progressCounters.Load(),
		"update_ts": time.Now().Unix(),
	})
}

func collectHeartbeat() cluster.Heartbeat {
	cpu, mem := loadStats()
	hb := cluster.Heartbeat{
		NodeID:  opt.nodeID,
		Name:    opt.nodeName,
		IP:      localIP(),
		OS:      runtime.GOOS + "/" + runtime.GOARCH,
		Version: "abcd-node-3.0",
		CPUPercent: cpu,
		MemPercent: mem,
		Ts:      time.Now().Unix(),
	}
	if t, ok := currentTaskID.Load().(string); ok {
		hb.RunningTask = t
	}
	// 并发模式: 聚合所有在跑任务(逗号串), master/前端按逗号拆
	var tasks []string
	runningSet.Range(func(k, v interface{}) bool {
		if s, ok := k.(string); ok {
			tasks = append(tasks, s)
		}
		return true
	})
	if len(tasks) > 0 {
		hb.RunningTask = strings.Join(tasks, ",")
	}
	return hb
}

func joinTargets(ts []string) string {
	s := ""
	for i, t := range ts {
		if i > 0 {
			s += ","
		}
		s += t
	}
	return s
}

// batchHasSyntax 批内是否含测绘引擎语法查询串(icp.name=公司名等) —
// 引擎分流判定: 语法批走Hunter独跑, 与master灌批分桶共用cluster.IsSyntaxQuery口径
func batchHasSyntax(targets []string) bool {
	for _, t := range targets {
		if cluster.IsSyntaxQuery(t) {
			return true
		}
	}
	return false
}

// hasDomainTarget 目标里是否含域名(非纯IP/CIDR/URL也算)
func hasDomainTarget(targets []string) bool {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if i := strings.Index(t, "://"); i >= 0 {
			t = t[i+3:]
		}
		if i := strings.IndexAny(t, "/"); i >= 0 {
			t = t[:i]
		}
		if i := strings.LastIndex(t, ":"); i >= 0 {
			t = t[:i]
		}
		for _, r := range t {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				return true // 含字母=域名
			}
		}
	}
	return false
}

// availableMapEngines 从Redis apiconfig提取已配key的引擎列表
func availableMapEngines() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	yml, err := rdb.Get(ctx, "cluster:apiconfig").Result()
	if err != nil {
		return nil
	}
	var engines []string
	if strings.Contains(yml, "hunter:") {
		engines = append(engines, "hunter")
	}
	if strings.Contains(yml, "fofa:") {
		engines = append(engines, "fofa")
	}
	if strings.Contains(yml, "quake:") {
		engines = append(engines, "quake")
	}
	return engines
}
