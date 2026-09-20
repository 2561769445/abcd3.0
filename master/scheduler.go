package master

import (
	"database/sql"
	"os"
	"strings"
	"sync"

	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"abcd/cluster"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

// nodeLive 心跳快照(来自Redis)
type nodeLive struct {
	ID         string  `json:"node_id"`
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	OS         string  `json:"os"`
	Version    string  `json:"version"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	RunningTask string `json:"running_task"`
	MaxConcurrent int `json:"max_concurrent"`
	Ts         int64   `json:"ts"`
}

// startScheduler 调度引擎: 每5s把pending任务派发到最优节点; 同步节点心跳到PG; 回收超时任务
func startScheduler(ctx context.Context, rdb *redis.Client) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncNodes(ctx, rdb)
			dispatchScheduled(ctx)
			dispatchTasks(ctx, rdb)
			syncProgress(ctx, rdb)
			recoverStalled(ctx, rdb)
			reclaimPullInflight(ctx, rdb) // 死节点在途批搬回公共队列(必须先于判done的finishScanning)
			finishScanning(ctx, rdb)
		}
	}
}

// syncNodes Redis心跳 → PG nodes表 + 离线检测
func syncNodes(ctx context.Context, rdb *redis.Client) {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	var stale []string
	for id, raw := range all {
		var probe nodeLive
		if json.Unmarshal([]byte(raw), &probe) == nil && now-probe.Ts > 3600 {
			stale = append(stale, id) // 1小时无心跳的残留节点记录清理
			continue
		}
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		online := now-n.Ts < 60
		var weight int
		_ = db.QueryRow(`SELECT weight FROM nodes WHERE id=$1`, id).Scan(&weight)
		_, err := db.Exec(`INSERT INTO nodes (id,name,ip,os,version,online,cpu_percent,mem_percent,running_task,last_heartbeat)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, ip=EXCLUDED.ip, os=EXCLUDED.os,
				version=EXCLUDED.version, online=EXCLUDED.online, cpu_percent=EXCLUDED.cpu_percent,
				mem_percent=EXCLUDED.mem_percent, running_task=EXCLUDED.running_task, last_heartbeat=now()`,
			id, n.Name, n.IP, n.OS, n.Version, online, n.CPUPercent, n.MemPercent, n.RunningTask)
		if err != nil {
			gologger.Warning().Msgf("节点落库失败 %s: %v", id, err)
		}
	}
	// PG里在线但心跳已消失的 → 置离线
	_, _ = db.Exec(`UPDATE nodes SET online=false WHERE online=true AND last_heartbeat < now() - interval '60 seconds'`)
	// 心跳消失超1小时的死节点行(换ID重启/退役) → 删除, 与Redis stale清理对齐
	_, _ = db.Exec(`DELETE FROM nodes WHERE last_heartbeat < now() - interval '1 hour'`)
	if len(stale) > 0 {
		rdb.HDel(ctx, cluster.HashNodes, stale...)
	}
}

// pickBestNode 按负载评分选节点: (100-cpu) + (100-mem) + weight*5, 空闲优先
func pickBestNode(ctx context.Context, rdb *redis.Client, excludeBusy bool) (string, bool) {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return "", false
	}
	now := time.Now().Unix()
	best := ""
	bestScore := -1.0
	for id, raw := range all {
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		if now-n.Ts >= 60 {
			continue // 离线
		}
		scorePenalty := 0.0
		if excludeBusy && n.RunningTask != "" {
			// 并发节点未达上限仍有接单余量(降权但不禁入)
			running := len(strings.Split(n.RunningTask, ","))
			if n.MaxConcurrent <= 0 || running >= n.MaxConcurrent {
				continue
			}
			scorePenalty = 30
		}
		var weight int
		_ = db.QueryRow(`SELECT weight FROM nodes WHERE id=$1`, id).Scan(&weight)
		if weight <= 0 {
			weight = 10
		}
		score := (100-n.CPUPercent)*0.4 + (100-n.MemPercent)*0.2 + float64(weight)*4 - float64(scorePenalty)
		if score > bestScore {
			bestScore = score
			best = id
		}
	}
	return best, best != ""
}

// dispatchScheduled 定时/周期任务到期转pending
// cron_expr格式: 纯数字N = 每N分钟循环重跑; "@once 时间"未支持; 空串=一次性
func dispatchScheduled(ctx context.Context) {
	// scheduled状态 → next_run到期 → pending
	db.Exec(`UPDATE tasks SET status='pending' WHERE status='scheduled' AND next_run IS NOT NULL AND next_run <= now()`)
	// 周期任务: done + cron_expr为纯数字分钟数 + 结束超过周期 → 生成新一轮pending
	rows, err := db.Query(`SELECT id, name, targets, target_count, ports, options, assigned_node, cron_expr FROM tasks WHERE status='done' AND cron_expr ~ '^[0-9]+$' AND finished_at < now() - (cron_expr || ' minutes')::interval`)
	if err != nil {
		return
	}
	type rt struct {
		id, name, targets, ports, options, assigned, cron string
		count                                              int
	}
	var list []rt
	for rows.Next() {
		var r rt
		_ = rows.Scan(&r.id, &r.name, &r.targets, &r.count, &r.ports, &r.options, &r.assigned, &r.cron)
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		newID := r.id + "-r" + time.Now().Format("0102150405")
		_, err := db.Exec(`INSERT INTO tasks (id,name,targets,target_count,ports,options,assigned_node,status,cron_expr,next_run)
			VALUES ($1,$2,$3,$4,$5, jsonb_set($6,'{scan_phase}','""'::jsonb),$7,'pending',$8, now() + ($8 || ' minutes')::interval)`,
			newID, r.name, r.targets, r.count, r.ports, r.options, r.assigned, r.cron)
		if err == nil {
			// 母任务标记为已完成周期轮, 不再重复克隆
			db.Exec(`UPDATE tasks SET status='archived' WHERE id=$1`, r.id)
		}
	}
}

// dispatchTasks pending任务入Redis队列(指定节点专属队列或公共队列)
func dispatchTasks(ctx context.Context, rdb *redis.Client) {
	rows, err := db.Query(`SELECT id, assigned_node, name, targets, ports, options FROM tasks WHERE status='pending' LIMIT 50`)
	if err != nil {
		return
	}
	defer rows.Close()
	type pending struct {
		id, assigned, name, targets, ports, options string
	}
	var list []pending
	for rows.Next() {
		var p pending
		_ = rows.Scan(&p.id, &p.assigned, &p.name, &p.targets, &p.ports, &p.options)
		list = append(list, p)
	}
	rows.Close()

	for _, p := range list {
		var targets []string
		if json.Unmarshal([]byte(p.targets), &targets) != nil {
			targets = []string{p.targets}
		}
		var opts cluster.ScanOptions
		_ = json.Unmarshal([]byte(p.options), &opts)

		// pull模式: 工作项(目标逐条)入工作队列, 描述子推给所有在线节点认领
		if opts.Mode == "pull" {
			if dispatchPullTask(ctx, rdb, p.id, p.name, p.ports, &opts, targets) {
				db.Exec(`UPDATE tasks SET status='queued', started_at=now() WHERE id=$1`, p.id)
				gologger.Info().Msgf("pull任务已派发: %s 工作项=%d", p.id, len(targets))
			}
			continue
		}

		// v52 大任务自动转pull: 目标数超阈值时切拉模式 — 断点续跑(节点挂了工作项回队列被别的节点领走),
		// 肥瘦自动均衡; 阈值环境变量ABCD_PULL_THRESHOLD(默认2000)
		if int64(len(targets)) > pullThreshold() {
			opts.Mode = "pull"
			// 传指针: dispatchPullTask内部算出的ScanPhase必须对调用者可见 —
			// 值传递时返回后旧opts(scan_phase空)回写DB会覆盖内部回写的正确值,
			// 判空逻辑用错队列键(无后缀 vs :ports), 派发后50秒任务被误判"无产出done"(2026-09-14事故)
			if dispatchPullTask(ctx, rdb, p.id, p.name, p.ports, &opts, targets) {
				db.Exec(`UPDATE tasks SET status='queued', started_at=now() WHERE id=$1`, p.id)
				gologger.Info().Msgf("大任务自动转pull: %s 目标=%d 阈值=%d 阶段=%s",
					p.id, len(targets), pullThreshold(), opts.ScanPhase)
			}
			continue
		}

		task := cluster.Task{
			ID:      p.id,
			Targets: targets,
			Ports:   p.ports,
			Options: opts,
		}
		// 指定节点但离线 → 保持pending等待
		queue := cluster.QueueTasks
		if p.assigned != "" {
			if !nodeOnline(ctx, rdb, p.assigned) {
				continue
			}
			queue = cluster.QueueNodePrefix + p.assigned
		}
		// v60(N9): 先原子占位(CAS pending→queued)再入队 — 之前LPush后UPDATE失败会让任务
		// 留pending下个tick再推一份, 双节点并发跑同一任务
		res, err := db.Exec(`UPDATE tasks SET status='queued', started_at=now() WHERE id=$1 AND status='pending'`, p.id)
		if err != nil || nRows(res) == 0 {
			continue // 已被其他tick派发或DB异常, 跳过
		}
		b, _ := json.Marshal(task)
		if err := rdb.LPush(ctx, queue, string(b)).Err(); err != nil {
			gologger.Warning().Msgf("任务入队失败 %s: %v", p.id, err)
			db.Exec(`UPDATE tasks SET status='pending', started_at=NULL WHERE id=$1 AND status='queued'`, p.id)
			continue
		}
		gologger.Info().Msgf("任务已派发: %s -> %s", p.id, queue)
	}
}

// dispatchPullTask pull模式派发: 工作项RPUSH进queue:pull:{id}, 描述子(空Targets)推所有在线节点专属队列。
// 节点领到描述子后自行BLPOP工作项, 谁空闲谁多干, 节点中途宕机不丢工作(项目回到队列)。
func dispatchPullTask(ctx context.Context, rdb *redis.Client, id, name, ports string, opts *cluster.ScanOptions, targets []string) bool {
	// 阶段路由(未显式指定时): 测绘语法/域名→map起(测绘只拉资产, 资产批回流全员认领),
	// IP/CIDR→ports起, 纯URL→单阶段(本身就是资产直接分批扫)
	if opts.ScanPhase == "" {
		opts.ScanPhase = scanPhaseFor(targets)
		db.Exec(`UPDATE tasks SET options=$2 WHERE id=$1`, id, mustJSON(opts)) // 转段判定读DB, 必须回写
	}
	// 幂等: 已建队列(重派场景)不重复灌工作项
	// v60(N6): 同时校验PullTotal键存在 — stop后子进程可能灌回半截URL造成僵尸队列,
	// 只看LLen>0会跳过重灌, retry拿旧目标跑完假done
	qkey := cluster.QueuePullKey(id, opts.ScanPhase)
	if n, _ := rdb.LLen(ctx, qkey).Result(); n > 0 {
		if total, terr := rdb.Get(ctx, cluster.PullTotalPrefix+id).Int(); terr == nil && total > 0 {
			return pushPullDescriptor(ctx, rdb, id, name, ports, *opts)
		}
		// total缺失=僵尸队列: 清掉走正常重灌
		delPullQueues(ctx, rdb, id)
	}
	// v53: 工作项按批打包(ABCD_PULL_BATCH默认100) — 46938个IP逐个入队=每IP一个子进程,
	// 指纹库加载开销×46938次; 按批入队后子进程开销摊薄, 单IP均耗降一个数量级
	batch := pullBatchSize()
	cleaned := make([]string, 0, len(targets))
	for _, t := range targets {
		if s := strings.TrimSpace(t); s != "" {
			cleaned = append(cleaned, s)
		}
	}
	if len(cleaned) == 0 {
		// 无有效工作项: 直接标记done, 防永久pending
		db.Exec(`UPDATE tasks SET status='done', finished_at=now() WHERE id=$1`, id)
		return false
	}
	// map阶段目标混有URL时(测绘导出脏数据/历史清单): URL直接预置进下一阶段ports键,
	// 不进:map — 否则引擎把URL当查询串发Hunter("字段http不支持查询"+3次重试退避+3s令牌),
	// 每个脏URL耗~35秒, 63批拖15小时(2026-09-15事故)
	mapBatch, urlBatch := cleaned, []string(nil)
	if opts.ScanPhase == "map" {
		mapBatch = make([]string, 0, len(cleaned))
		urlBatch = make([]string, 0)
		for _, t := range cleaned {
			if strings.Contains(t, "://") {
				urlBatch = append(urlBatch, t)
			} else {
				mapBatch = append(mapBatch, t)
			}
		}
	}
	items := make([]interface{}, 0, (len(mapBatch)+batch-1)/batch)
	for i := 0; i < len(mapBatch); i += batch {
		end := i + batch
		if end > len(mapBatch) {
			end = len(mapBatch)
		}
		items = append(items, strings.Join(mapBatch[i:end], "\n"))
	}
	if len(items) > 0 {
		if err := rdb.RPush(ctx, qkey, items...).Err(); err != nil {
			gologger.Warning().Msgf("pull工作队列写入失败 %s: %v", id, err)
			return false
		}
	}
	if len(urlBatch) > 0 {
		uitems := make([]interface{}, 0, (len(urlBatch)+batch-1)/batch)
		for i := 0; i < len(urlBatch); i += batch {
			end := i + batch
			if end > len(urlBatch) {
				end = len(urlBatch)
			}
			uitems = append(uitems, strings.Join(urlBatch[i:end], "\n"))
		}
		if err := rdb.RPush(ctx, cluster.QueuePullKey(id, "ports"), uitems...).Err(); err != nil {
			gologger.Warning().Msgf("pull初始URL预置ports失败 %s: %v", id, err)
			return false
		}
		// 初始URL是下一阶段工作项: 与回流产物同口径累加phase2total, 转段时total重置才正确
		rdb.IncrBy(ctx, "task:pull:phase2total:"+id, int64(len(urlBatch)))
		rdb.Expire(ctx, "task:pull:phase2total:"+id, 24*time.Hour)
	}
	rdb.Set(ctx, cluster.PullTotalPrefix+id, len(mapBatch), 0)
	rdb.Del(ctx, cluster.PullDonePrefix+id, cluster.PullLivePrefix+id)
	gologger.Info().Msgf("pull任务工作队列: %s 本阶段目标=%d URL预置下一阶段=%d 批大小=%d 批数=%d", id, len(mapBatch), len(urlBatch), batch, len(items))
	return pushPullDescriptor(ctx, rdb, id, name, ports, *opts)
}

// pullBatchSize pull工作项批大小(ABCD_PULL_BATCH环境变量, 默认25个目标/批)
// 25=实测平衡点: 100/批时单批PoC阶段(31k URL)要30-60分钟才出一次done计数, 前端像死了;
// 25/批单批~10分钟出计数, 进程开销仅×4无感
func pullBatchSize() int {
	if v := os.Getenv("ABCD_PULL_BATCH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 25
}

// pushPullDescriptor pull描述子(Task.Targets为空+Options.Mode=pull)推给所有在线节点
func pushPullDescriptor(ctx context.Context, rdb *redis.Client, id, name, ports string, opts cluster.ScanOptions) bool {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	task := cluster.Task{ID: id, Name: name, Ports: ports, Options: opts, CreatedAt: now}
	b, _ := json.Marshal(task)
	pushed := 0
	for nodeID := range all {
		if !nodeOnline(ctx, rdb, nodeID) {
			continue
		}
		if err := rdb.LPush(ctx, cluster.QueueNodePrefix+nodeID, string(b)).Err(); err != nil {
			gologger.Warning().Msgf("pull描述子推送失败 %s -> %s: %v", id, nodeID, err)
			continue
		}
		pushed++
	}
	return pushed > 0
}

// pullThreshold 大任务自动转pull的目标数阈值(ABCD_PULL_THRESHOLD环境变量, 默认2000)
func pullThreshold() int64 {
	if v := os.Getenv("ABCD_PULL_THRESHOLD"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 2000
}

// delPullQueues 清pull任务全部阶段队列键(含单阶段老格式) — 终态/删除/重灌场景
func delPullQueues(ctx context.Context, rdb *redis.Client, id string) {
	keys := []string{cluster.QueuePullPrefix + id, cluster.PullLivePrefix + id}
	for _, p := range cluster.PullPhases {
		keys = append(keys, cluster.QueuePullKey(id, p))
	}
	rdb.Del(ctx, keys...)
}

// purgeQueueByID 整队列轮转一圈剔除指定任务描述子(保序完整一圈): 弹出非目标元素回推,
// 回推到首个元素时停。判死/完成/转段时调用, 防僵尸描述子堆积致后续任务排队空转30s/个。
// (v60 N7轮转语义: 原版遇首个非目标就break会漏清队头是别任务时压后面的本任务描述子)
func purgeQueueByID(ctx context.Context, rdb *redis.Client, qkey, taskID string) {
	var firstKept string
	first := true
	for {
		raw, err := rdb.LPop(ctx, qkey).Result()
		if err != nil {
			return // 队列空
		}
		var probe cluster.Task
		if json.Unmarshal([]byte(raw), &probe) == nil && probe.ID == taskID {
			continue // 丢弃本任务描述子, 继续弹
		}
		if first {
			firstKept = raw
			first = false
		} else if raw == firstKept {
			// 转了一整圈, 队列已全扫过
			return
		}
		rdb.RPush(ctx, qkey, raw)
		if raw == firstKept {
			return
		}
	}
}

// purgeNodeQueues 清理所有节点专属队列里的本任务描述子(判死/完成/转段时调用)
func purgeNodeQueues(ctx context.Context, rdb *redis.Client, id string) {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return
	}
	for nodeID := range all {
		purgeQueueByID(ctx, rdb, cluster.QueueNodePrefix+nodeID, id)
	}
}

// reclaimPullInflight 回收死节点的pull在途工作项(100%不丢机制):
// 节点BRPopLPush领取的工作项死在半路时, 在线节点的批次会被它一直扣着不释放。
// 每 tick 扫全部 pullproc 键(SCAN兜住心跳已消失的节点), 节点离线(心跳≥60s或不在hash)
// 就把它的在途项按TaskID+Phase搬回公共队列给在线节点重抢。
// 挂在finishScanning之前: 判done/转段必先经过回收, 队列空才真收尾, 不会丢批。
// 幂等: 搬走即LRem, 下个tick该键已空; 与节点启动自愈并发最坏=同批双扫(资产唯一键挡重, 无害)。
// 时钟漂移误判(节点活着但心跳慢107s)同样只是双扫, 代价可接受。
func reclaimPullInflight(ctx context.Context, rdb *redis.Client) {
	all, _ := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	now := time.Now().Unix()
	iter := rdb.Scan(ctx, 0, cluster.QueuePullProcPrefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		procKey := iter.Val()
		nodeID := strings.TrimPrefix(procKey, cluster.QueuePullProcPrefix)
		if nodeID == "" {
			continue
		}
		// 在线节点跳过: 它的在途项正在被正常执行, 等它跑完LRem
		if raw, ok := all[nodeID]; ok {
			var n nodeLive
			if json.Unmarshal([]byte(raw), &n) == nil && now-n.Ts < 60 {
				continue
			}
		}
		items, err := rdb.LRange(ctx, procKey, 0, -1).Result()
		if err != nil {
			continue
		}
		moved, dropped := 0, 0
		for _, raw := range items {
			var inf cluster.PullInflight
			if json.Unmarshal([]byte(raw), &inf) != nil || inf.TaskID == "" {
				rdb.LRem(ctx, procKey, 0, raw) // 脏数据直接清
				dropped++
				continue
			}
			// 任务已终态/已删 → 在途项直接丢弃(不回灌成孤儿队列)
			var status string
			if db.QueryRow(`SELECT status FROM tasks WHERE id=$1`, inf.TaskID).Scan(&status) != nil ||
				(status != "queued" && status != "scanning") {
				rdb.LRem(ctx, procKey, 0, raw)
				dropped++
				continue
			}
			if rdb.RPush(ctx, cluster.QueuePullKey(inf.TaskID, inf.Phase), inf.Work).Err() == nil {
				rdb.LRem(ctx, procKey, 0, raw)
				moved++
			}
		}
		if moved > 0 || dropped > 0 {
			gologger.Info().Msgf("回收离线节点在途项: %s 搬回=%d 丢弃=%d", nodeID, moved, dropped)
		}
	}
}

// purgeProcQueues 清全部节点在途队列里该任务的条目(stop/删除/终态收尾时调用, 条目直接丢弃)
func purgeProcQueues(ctx context.Context, rdb *redis.Client, taskID string) {
	iter := rdb.Scan(ctx, 0, cluster.QueuePullProcPrefix+"*", 100).Iterator()
	for iter.Next(ctx) {
		procKey := iter.Val()
		items, err := rdb.LRange(ctx, procKey, 0, -1).Result()
		if err != nil {
			continue
		}
		for _, raw := range items {
			var inf cluster.PullInflight
			if json.Unmarshal([]byte(raw), &inf) == nil && inf.TaskID == taskID {
				rdb.LRem(ctx, procKey, 0, raw)
			}
		}
	}
}

// nodeQueuesHave 任一节点队列里已堆有本任务描述子(排队中) — recoverStalled重推前查重,
// 防"每10分钟堆一份"的膨胀(2026-09-14实测32个/节点, 后续任务排队16分钟+)
func nodeQueuesHave(ctx context.Context, rdb *redis.Client, id string) bool {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return false
	}
	for nodeID := range all {
		items, err := rdb.LRange(ctx, cluster.QueueNodePrefix+nodeID, 0, -1).Result()
		if err != nil {
			continue
		}
		for _, raw := range items {
			var probe cluster.Task
			if json.Unmarshal([]byte(raw), &probe) == nil && probe.ID == id {
				return true
			}
		}
	}
	return false
}

// pullQLen 全阶段队列长度总和 — 完成判定/僵尸检测看的是"还有没有任何工作项"
func pullQLen(ctx context.Context, rdb *redis.Client, id string) int64 {
	n, _ := rdb.LLen(ctx, cluster.QueuePullPrefix + id).Result()
	for _, p := range cluster.PullPhases {
		v, _ := rdb.LLen(ctx, cluster.QueuePullKey(id, p)).Result()
		n += v
	}
	return n
}

// scanPhaseFor pull任务的阶段路由: URL目标本身是资产(单阶段分批扫);
// 测绘语法(含=)与域名目标需要测绘扩展→map起(测绘产物回流浪队列全员认领);
// 其余(IP/CIDR/IP段)→ports起
func scanPhaseFor(targets []string) string {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" || strings.Contains(t, "://") {
			continue
		}
		if strings.Contains(t, "=") {
			return "map" // icp.name= / domain= / ip= 等测绘查询
		}
		for _, r := range t {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				return "map" // 域名: 需测绘补资产
			}
		}
	}
	return "ports"
}

// mustJSON 序列化(失败返回空对象串, 调用处只用于options回写, 不致命)
func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func nodeOnline(ctx context.Context, rdb *redis.Client, nodeID string) bool {
	raw, err := rdb.HGet(ctx, cluster.HashNodes, nodeID).Result()
	if err != nil {
		return false
	}
	var n nodeLive
	if json.Unmarshal([]byte(raw), &n) != nil {
		return false
	}
	return time.Now().Unix()-n.Ts < 60
}

// syncProgress 节点上报的阶段进度(Redis hash) → PG tasks.progress/stage
// pull任务改用工作队列计数: progress=done/total百分比, stage=拉取中(done/total)
func syncProgress(ctx context.Context, rdb *redis.Client) {
	rows, err := db.Query(`SELECT id, options FROM tasks WHERE status IN ('queued','scanning','stopping')`)
	if err != nil {
		return
	}
	defer rows.Close()
	type tk struct {
		id, options string
	}
	var ids []tk
	for rows.Next() {
		var t tk
		_ = rows.Scan(&t.id, &t.options)
		ids = append(ids, t)
	}
	rows.Close()
	for _, t := range ids {
		var opts cluster.ScanOptions
		_ = json.Unmarshal([]byte(t.options), &opts)
		if opts.Mode == "pull" {
			total, _ := rdb.Get(ctx, cluster.PullTotalPrefix+t.id).Int()
			if total <= 0 {
				// total键可能已清(TTL) — 从队列长度+done推
				if qlen := pullQLen(ctx, rdb, t.id); qlen > 0 {
					done, _ := rdb.Get(ctx, cluster.PullDonePrefix+t.id).Int()
					total = int(qlen) + done
				}
			}
			done, _ := rdb.Get(ctx, cluster.PullDonePrefix+t.id).Int()
			// 批内实时进度: 显示=已完成批的条目数done+在跑批已查完的关键词live
			// (live由子进程每查完一个关键词INCR, 整批完成时对冲扣回 — 不会双计)。
			// 对冲双保险: 新父进程DecrBy + master按done跳增量补扣(旧父进程热替换场景兜底)
			liveHedge.Lock()
			if prev, had := liveHedge.m[t.id]; had && int64(done) > prev {
				rdb.DecrBy(ctx, cluster.PullLivePrefix+t.id, int64(done)-prev)
			}
			liveHedge.m[t.id] = int64(done)
			liveHedge.Unlock()
			live, _ := rdb.Get(ctx, cluster.PullLivePrefix+t.id).Int()
			if live < 0 {
				live = 0 // 对冲过头(双对冲/子进程被杀), 钳位
			}
			display := done + live
			if total > 0 {
				pct := display * 100 / total
				if pct > 100 {
					pct = 100 // 转段竞态下done可短时超total, 封顶防"136%"怪象
				}
				stage := fmt.Sprintf("拉取中 %d/%d", display, total)
				if opts.ScanPhase == "map" {
					stage = fmt.Sprintf("测绘中 %d/%d", display, total)
				}
				// deep批单批要跑很久, 批间进度不动看着像卡死 —
				// 拼上节点ProgressHook上报的批内细粒度计数给"在动"的观感
				if m2, e := rdb.HGetAll(ctx, cluster.ProgressPrefix+t.id).Result(); e == nil && m2["stage_cn"] != "" {
					stage += " · " + m2["stage_cn"]
				}
				db.Exec(`UPDATE tasks SET progress=$1, stage=$2 WHERE id=$3 AND status IN ('queued','scanning','stopping')`,
					pct, stage, t.id)
			}
			continue
		}
		m, err := rdb.HGetAll(ctx, cluster.ProgressPrefix+t.id).Result()
		if err != nil || len(m) == 0 {
			continue
		}
		pct, stage := "", ""
		if v, ok := m["progress"]; ok {
			pct = v
		}
		if v, ok := m["stage_cn"]; ok {
			stage = v
		}
		// v52 ETA: 细粒度计数存在时按滑动脉冲速率估剩余时间; 更新入库stage尾缀
		if done, derr := strconv.ParseInt(m["done_count"], 10, 64); derr == nil {
			if total, terr := strconv.ParseInt(m["total_count"], 10, 64); terr == nil && total > 0 && done > 0 {
				if ts, tserr := strconv.ParseInt(m["update_ts"], 10, 64); tserr == nil {
					eta := estimateETA(t.id, done, total, ts)
					if eta > 0 {
						stage = fmt.Sprintf("%s (剩余约%s)", stage, fmtDuration(eta))
					}
				}
			}
		}
		if pct != "" || stage != "" {
			if pct == "" {
				pct = "0"
			}
			db.Exec(`UPDATE tasks SET progress=$1, stage=$2 WHERE id=$3 AND status IN ('queued','scanning','stopping')`, pct, stage, t.id)
		}
	}
}

// etaTracker 滑动速率: taskID → 上次(计数, 时间戳), 两次采样差值算每秒完成数
var etaTracker = struct {
	sync.Mutex
	m map[string]etaSample
}{m: make(map[string]etaSample)}

type etaSample struct {
	done int64
	ts   int64
}

// liveHedge pull任务done历史值: 批完成(done跳增N)时补扣live N — 批内实时计数对冲
var liveHedge = struct {
	sync.Mutex
	m map[string]int64
}{m: make(map[string]int64)}

// forgetLiveHedge 任务终态时丢弃对冲记忆
func forgetLiveHedge(taskID string) {
	liveHedge.Lock()
	delete(liveHedge.m, taskID)
	liveHedge.Unlock()
}

// forgetETA 任务终态时丢弃采样条目(map不清理随任务数无限增长)
func forgetETA(taskID string) {
	etaTracker.Lock()
	delete(etaTracker.m, taskID)
	etaTracker.Unlock()
}

// estimateETA 按最近两次上报的速率外推剩余秒数; 速率过慢(<0.1/s)返回0不显示
func estimateETA(taskID string, done, total, ts int64) int64 {
	etaTracker.Lock()
	defer etaTracker.Unlock()
	prev, ok := etaTracker.m[taskID]
	etaTracker.m[taskID] = etaSample{done: done, ts: ts}
	if !ok || prev.done >= done || ts <= prev.ts {
		return 0
	}
	rate := float64(done-prev.done) / float64(ts-prev.ts) // 个/秒
	if rate < 0.1 {
		return 0
	}
	remain := total - done
	if remain <= 0 {
		return 0
	}
	return int64(float64(remain) / rate)
}

func fmtDuration(sec int64) string {
	switch {
	case sec < 90:
		return fmt.Sprintf("%d秒", sec)
	case sec < 5400:
		return fmt.Sprintf("%d分钟", (sec+30)/60)
	default:
		return fmt.Sprintf("%.1f小时", float64(sec)/3600.0)
	}
}

// recoverStalled 卡死任务回收: queued超30分钟无人领 / scanning超6小时且节点已不在线跑它
func recoverStalled(ctx context.Context, rdb *redis.Client) {
	// queued: 派发后30分钟仍在队列(节点全挂/掉任务)
	// pull任务不回pending(工作项已在Redis队列, 回pending会重复灌) — 只重新推描述子唤醍节点
	rows, err := db.Query(`SELECT id, options FROM tasks WHERE status='queued' AND started_at < now() - interval '30 minutes'`)
	if err != nil {
		return
	}
	defer rows.Close()
	var pullIDs []string
	var normalIDs []string
	for rows.Next() {
		var id, options string
		_ = rows.Scan(&id, &options)
		var opts cluster.ScanOptions
		_ = json.Unmarshal([]byte(options), &opts)
		if opts.Mode == "pull" {
			pullIDs = append(pullIDs, id)
		} else {
			normalIDs = append(normalIDs, id)
		}
	}
	rows.Close()
	for _, id := range normalIDs {
		db.Exec(`UPDATE tasks SET status='pending', assigned_node='' WHERE id=$1`, id)
	}
	// pull任务queued超30min: 工作项还在队列说明节点没领或领完描述子丢了 → 重推描述子
	// v59: 幂等防护 — 每个任务在"描述子在飞"期间只推一次(recoverStallGuard键TTL 10min),
	// 否则每5min tick都推, 节点队列堆积5万+描述子(实测事故)
	for _, id := range pullIDs {
		qlen := pullQLen(ctx, rdb, id)
		if qlen > 0 {
			// v60(N4): 有节点正在跑该pull任务就跳过重推 — 否则deep长任务每10min向全节点
			// 堆一份描述子, 任务收尾后节点要逐个空转30s吞掉, 完成被拖后几十分钟
			all, _ := rdb.HGetAll(ctx, cluster.HashNodes).Result()
			anyBusy := false
			now := time.Now().Unix()
			for _, raw := range all {
				var n nodeLive
				if json.Unmarshal([]byte(raw), &n) == nil && now-n.Ts < 60 &&
					strings.Contains(n.RunningTask, "pull:"+id) {
					anyBusy = true
					break
				}
			}
			if anyBusy {
				continue
			}
			// 描述子已在节点队列排队(尚未被领) → 不重复推, 防每10min堆一份膨胀
			if nodeQueuesHave(ctx, rdb, id) {
				continue
			}
			guard := "task:despatcher:" + id
			ok, err := rdb.SetNX(ctx, guard, 1, 10*time.Minute).Result()
			if err != nil || !ok {
				continue // 已有描述子在飞(10min内推过)
			}
			var name, ports, options string
			db.QueryRow(`SELECT name, ports, options FROM tasks WHERE id=$1`, id).Scan(&name, &ports, &options)
			var opts cluster.ScanOptions
			_ = json.Unmarshal([]byte(options), &opts)
			if pushPullDescriptor(ctx, rdb, id, name, ports, opts) {
				gologger.Info().Msgf("pull任务重推描述子: %s 剩余=%d", id, qlen)
			}
		}
	}
	// scanning: 6小时无结束 + 节点心跳里没人正在跑它 → 回收(避免长任务被误杀)
	rows, err2 := db.Query(`SELECT id FROM tasks WHERE status='scanning' AND started_at < now() - interval '6 hours'`)
	if err2 != nil {
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}
	all, err3 := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err3 != nil {
		return
	}
	now := time.Now().Unix()
	running := map[string]bool{}
	for _, raw := range all {
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) == nil && now-n.Ts < 60 && n.RunningTask != "" {
			// v60(N3): 并发节点心跳是逗号串"t1,t2", 整串做key导致单任务永远匹配不到→超6h任务被重复派发
			for _, part := range strings.Split(n.RunningTask, ",") {
				if p := strings.TrimSpace(part); p != "" {
					running[p] = true
				}
			}
		}
	}
	for _, id := range ids {
		if !running[id] {
			db.Exec(`UPDATE tasks SET status='pending', assigned_node='' WHERE id=$1 AND status='scanning'`, id)
		}
	}
}

// finishScanning 节点上报state=done/failed/stopped → 更新PG任务状态
// pull任务不走节点state, 由队列耗尽+无人认领判定完成(pullTaskDone)
func finishScanning(ctx context.Context, rdb *redis.Client) {
	// 注意包含stopping: 停止指令下发后节点回报stopped也要能落状态
	rows, err := db.Query(`SELECT id, options FROM tasks WHERE status IN ('queued','scanning','stopping')`)
	if err != nil {
		return
	}
	defer rows.Close()
	type tk struct {
		id, options string
	}
	var ids []tk
	for rows.Next() {
		var t tk
		_ = rows.Scan(&t.id, &t.options)
		ids = append(ids, t)
	}
	rows.Close()
	for _, t := range ids {
		var opts cluster.ScanOptions
		_ = json.Unmarshal([]byte(t.options), &opts)
		if opts.Mode == "pull" {
			pullTaskDone(ctx, rdb, t.id)
			continue
		}
		state, err := rdb.Get(ctx, cluster.TaskStatePrefix+id2state(t.id)).Result()
		if err != nil {
			continue
		}
		// state格式: status|extra
		st := state
		if i := indexOf(st, '|'); i >= 0 {
			st = st[:i]
		}
		switch st {
		case "scanning":
			db.Exec(`UPDATE tasks SET status='scanning' WHERE id=$1`, t.id)
		case "done":
			db.Exec(`UPDATE tasks SET status='done', finished_at=now() WHERE id=$1`, t.id)
			notifyTaskDone(t.id) // webhook任务完成通知
			settleTask(ctx, rdb, t.id)
		case "failed":
			db.Exec(`UPDATE tasks SET status='failed', finished_at=now() WHERE id=$1`, t.id)
			settleTask(ctx, rdb, t.id)
		case "stopped":
			db.Exec(`UPDATE tasks SET status='stopped', finished_at=now() WHERE id=$1`, t.id)
			settleTask(ctx, rdb, t.id)
		}
	}
}

// settleTask 任务终态统一回收: 进度hash/状态键/ETA采样/通知去重条目。
// 这些key没有TTL, 不清就永久留在Redis和内存map里随任务数线性堆积。
func settleTask(ctx context.Context, rdb *redis.Client, id string) {
	rdb.Del(ctx, cluster.TaskStatePrefix+id, cluster.ProgressPrefix+id, "task:pull:phase2total:"+id, cluster.PullLivePrefix+id)
	forgetETA(id)
	forgetLiveHedge(id)
	ForgetTask(id)
}

func id2state(id string) string { return id }

// pullTaskDone pull任务完成判定: 工作队列空 AND 没有任何节点心跳正在跑它 → done
func pullTaskDone(ctx context.Context, rdb *redis.Client, id string) {
	// stopping中的任务不做任何推进: 转deep描述子会让已停任务复活,
	// done落库会和handleStopTask的stopped互相踩(两个tick并发写终态)
	var status, options string
	if db.QueryRow(`SELECT status, options FROM tasks WHERE id=$1`, id).Scan(&status, &options) != nil {
		return // 行已删
	}
	if status != "queued" && status != "scanning" {
		return
	}
	// 队列空: 再确认没有节点在跑该pull任务(心跳running_task含它=子任务未收尾)
	all, _ := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	now := time.Now().Unix()
	busy := false
	for _, raw := range all {
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) != nil || now-n.Ts >= 60 {
			continue
		}
		if strings.Contains(n.RunningTask, "pull:"+id) {
			busy = true
			break
		}
	}
	if busy {
		return // 还有节点在收尾
	}
	var opts cluster.ScanOptions
	_ = json.Unmarshal([]byte(options), &opts)
	// 空判定只看当前阶段键: 下一阶段键里的回流产物是转段的输入, 不是在跑的工作项
	// (总和判定会与回流产物互相等待成死锁)
	if qlen, _ := rdb.LLen(ctx, cluster.QueuePullKey(id, opts.ScanPhase)).Result(); qlen > 0 {
		return
	}
	// 阶段推进: map(测绘)→ports(端口+Web探针)→deep(深度)→done。
	// 每段队列空+节点收工时, 查节点灌回的下一阶段工作项: 有→重置计数推下一阶段描述子;
	// 无→连续10次tick(50s)宽限后判空产出done(测绘0资产公司/端口阶段0 URL都走这条路)
	if opts.ScanPhase == "map" {
		advancePhase(ctx, rdb, id, opts, "ports", "测绘完成, 进入端口扫描阶段")
		return
	}
	if opts.ScanPhase == "" || opts.ScanPhase == "ports" {
		advancePhase(ctx, rdb, id, opts, "deep", "")
		return
	}
	db.Exec(`UPDATE tasks SET status='done', finished_at=now() WHERE id=$1`, id)
	notifyTaskDone(id)
	// 收尾清理: 队列/计数键 + 节点队列残留描述子(不删会排队空转30s/个)
	purgeNodeQueues(ctx, rdb, id)
	purgeProcQueues(ctx, rdb, id)
	delPullQueues(ctx, rdb, id)
	rdb.Del(ctx, cluster.PullTotalPrefix+id, cluster.PullDonePrefix+id, cluster.PullLivePrefix+id)
	settleTask(ctx, rdb, id)
	gologger.Info().Msgf("pull任务完成: %s", id)
}

// advancePhase 阶段转段: 下一阶段工作项已灌入则重置进度并推新描述子, 否则宽限计数后判空done
func advancePhase(ctx context.Context, rdb *redis.Client, id string, opts cluster.ScanOptions, next, logMsg string) {
	{
		qlen2, _ := rdb.LLen(ctx, cluster.QueuePullKey(id, next)).Result()
		if qlen2 == 0 {
			// 竞态宽限计数: 队列空但无下一阶段工作项 — 连续10次tick(50s)仍无 → 判0产出, 直接done
			k := "task:phase1wait:" + id
			n, _ := rdb.Incr(ctx, k).Result()
			rdb.Expire(ctx, k, 10*time.Minute)
			if n >= 10 {
				rdb.Del(ctx, k)
				db.Exec(`UPDATE tasks SET status='done', finished_at=now() WHERE id=$1`, id)
				notifyTaskDone(id)
				purgeNodeQueues(ctx, rdb, id) // 误判/真判死都清残留描述子
				delPullQueues(ctx, rdb, id)
				rdb.Del(ctx, cluster.PullTotalPrefix+id, cluster.PullDonePrefix+id)
				settleTask(ctx, rdb, id)
				gologger.Info().Msgf("阶段任务无产出, 任务完成: %s", id)
			}
			return
		}
		rdb.Del(ctx, "task:phase1wait:"+id)
		// 下一阶段工作项已就绪: 重置进度(total=产物条数[节点INCRBY累加]否则批数×25), 推新描述子。
		// GETDEL原子取走: 不删的话下一阶段子进程的INCRBY会叠在本阶段残留上, 总数虚高。
		pt := int64(0)
		if v, err := rdb.GetDel(ctx, "task:pull:phase2total:"+id).Int64(); err == nil && v > 0 {
			pt = v
		}
		if pt > 0 {
			rdb.Set(ctx, cluster.PullTotalPrefix+id, pt, 0)
		} else {
			rdb.Set(ctx, cluster.PullTotalPrefix+id, qlen2*25, 0) // 兜底: 批数×25近似条数
		}
		rdb.Del(ctx, cluster.PullDonePrefix+id, cluster.PullLivePrefix+id)
		opts.ScanPhase = next
		purgeNodeQueues(ctx, rdb, id) // 转段前清旧阶段描述子(旧键已空, 弹到只空转30s)
		if pushPullDescriptor(ctx, rdb, id, "", "", opts) {
			db.Exec(`UPDATE tasks SET options=$2 WHERE id=$1`, id, mustJSON(opts))
			if logMsg != "" {
				gologger.Info().Msgf("%s: %s 工作项=%d批", logMsg, id, qlen2)
			} else {
				gologger.Info().Msgf("任务进入阶段(%s): %s 工作项=%d批", next, id, qlen2)
			}
		}
	}
}

// nRows RowsAffected快捷
func nRows(res sql.Result) int64 {
	n, _ := res.RowsAffected()
	return n
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
