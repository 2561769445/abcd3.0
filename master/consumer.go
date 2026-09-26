package master

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"abcd/cluster"
	"abcd/ddout"

	"github.com/lib/pq"
	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

// resultBuf 内存攒批缓冲, 定时/定量批量写PG
type assetInsert struct {
	taskID, nodeID, assetType, ip, port, protocol, uri, domain, title, statusCode, finger, extra string
}

type vulnInsert struct {
	taskID, nodeID, source, vulnID, severity, target, detail, extra string
}

type credInsert struct {
	taskID, nodeID, service, target, detail string
}

// isCredential 判断GoPoc结果是否为弱口令/未授权类凭据
func isCredential(g ddout.GoPocsResultType) bool {
	kw := g.PocName + g.Description
	return strings.Contains(kw, "弱口令") || strings.Contains(kw, "未授权") || strings.Contains(kw, "Login") || strings.Contains(kw, "爆破成功")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var (
	assetChan = make(chan assetInsert, 20000)
	vulnChan  = make(chan vulnInsert, 20000)
	credChan  = make(chan credInsert, 20000)
)

func consumeQueue(ctx context.Context, rdb *redis.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		res, err := rdb.BRPop(ctx, 3*time.Second, cluster.QueueResults, cluster.QueueResultsRetry).Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if len(res) < 2 {
			continue
		}
		handleResult(res[1])
	}
}

func handleResult(payload string) {
	var env cluster.ResultEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		gologger.Warning().Msgf("结果信封解析失败: %v", err)
		return
	}
	// 驼峰键别名兜底: 注入测试常用TaskID/NodeID(大写驼峰), 与tag(task_id)差一个下划线,
	// Go json的大小写不敏感匹配跨不过下划线 → 静默解析成空task_id写成孤儿行
	if env.TaskID == "" || env.NodeID == "" {
		var alias struct {
			TaskID string `json:"TaskID"`
			NodeID string `json:"NodeID"`
		}
		_ = json.Unmarshal([]byte(payload), &alias)
		if env.TaskID == "" {
			env.TaskID = alias.TaskID
		}
		if env.NodeID == "" {
			env.NodeID = alias.NodeID
		}
	}
	if env.TaskID == "" {
		gologger.Warning().Msgf("结果信封缺task_id(键名不符), 丢弃: %.200s", payload)
		return
	}
	var msg ddout.OutputMessage
	if err := json.Unmarshal(env.Msg, &msg); err != nil {
		gologger.Warning().Msgf("结果消息解析失败: %v", err)
		return
	}

	switch msg.Type {
	case "GoPoc":
		vulnChan <- vulnInsert{
			taskID: env.TaskID, nodeID: env.NodeID, source: "gopoc",
			vulnID: msg.GoPoc.PocName, severity: normSeverity(msg.GoPoc.Security),
			target: msg.GoPoc.Target, detail: msg.GoPoc.ShowMsg,
			extra: string(env.Msg),
		}
		// 弱口令/未授权凭据独立台账
		if isCredential(msg.GoPoc) {
			credChan <- credInsert{
				taskID: env.TaskID, nodeID: env.NodeID,
				service: msg.GoPoc.PocName, target: msg.GoPoc.Target,
				detail: firstNonEmpty(msg.GoPoc.InfoLeft, msg.GoPoc.ShowMsg),
			}
		}
	case "Nuclei":
		// msg.Nuclei 字段带完整 ResultEvent JSON, 从中精提severity/templateID/target
		vulnID, sev, target := parseNucleiJSON(msg.Nuclei, msg.Show, msg.URI)
		vulnChan <- vulnInsert{
			taskID: env.TaskID, nodeID: env.NodeID, source: "nuclei",
			vulnID: vulnID, severity: sev,
			target: target, detail: msg.Show,
			extra: string(env.Msg),
		}
	default:
		assetChan <- assetInsert{
			taskID: env.TaskID, nodeID: env.NodeID, assetType: msg.Type,
			ip: msg.IP, port: msg.Port, protocol: msg.Protocol,
			uri: msg.URI, domain: msg.Domain,
			title: msg.Web.Title, statusCode: msg.Web.Status,
			finger: strings.Join(msg.Finger, ","),
			extra: string(env.Msg),
		}
	}
}

// normSeverity 统一等级为critical/high/medium/low/info(兼容中文)
func normSeverity(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "严重", "危急", "critical":
		return "critical"
	case "高危", "高", "high":
		return "high"
	case "中危", "中", "medium", "moderate":
		return "medium"
	case "低危", "低", "low":
		return "low"
	case "提示", "信息", "info", "informational", "unknown", "":
		return "info"
	}
	return t
}

// parseNucleiJSON 从ResultEvent JSON提取 templateID/severity/target
func parseNucleiJSON(raw, show, fallbackTarget string) (name, sev, target string) {
	name, sev, target = "", "", fallbackTarget
	if raw != "" {
		var ev struct {
			TemplateID string `json:"TemplateID"`
			Matched     string `json:"Matched"`
			Info        struct {
				Name string `json:"Name"`
				SeverityHolder struct {
					Severity string `json:"severity"`
				} `json:"SeverityHolder"`
			} `json:"Info"`
			// 小写键序列化(v71实测线上节点即此格式): template-id/matched-at带连字符,
			// Go json大小写不敏感匹配不到; info.severity是扁平字符串无SeverityHolder嵌套层
			TemplateID2 string `json:"template-id"`
			MatchedAt   string `json:"matched-at"`
			URL         string `json:"url"`
			Host        string `json:"host"`
			InfoLower   struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal([]byte(raw), &ev); err == nil {
			if ev.TemplateID != "" {
				name = ev.TemplateID
			} else if ev.TemplateID2 != "" {
				name = ev.TemplateID2
			}
			if ev.Info.SeverityHolder.Severity != "" {
				sev = normSeverity(ev.Info.SeverityHolder.Severity)
			} else if ev.InfoLower.Severity != "" {
				sev = normSeverity(ev.InfoLower.Severity)
			}
			if ev.Matched != "" {
				target = ev.Matched
			} else if ev.MatchedAt != "" {
				target = ev.MatchedAt
			} else if ev.URL != "" {
				target = ev.URL
			} else if ev.Host != "" {
				target = ev.Host
			}
		}
	}
	// 兜底: Show格式 "[template-id] [severity] matched"
	if name == "" || sev == "" {
		if f := strings.Fields(strings.TrimPrefix(show, "[Nuclei] ")); len(f) >= 3 && strings.HasPrefix(show, "[") {
			if name == "" {
				name = strings.Trim(f[0], "[]")
			}
			if sev == "" {
				sev = normSeverity(strings.Trim(f[1], "[]"))
			}
		}
	}
	if sev == "" {
		sev = "info"
	}
	return
}

// batchWriter 攒批写入: 每N条或每interval落地一次。
// 批量失败时降级逐条重试: 一条毒丸行(非法UTF-8等)只损失它自己,
// 整批丢弃会让后续每批都撞同一个错, 数据持续静默流失。
func batchWriter[T any](ctx context.Context, ch chan T, kind string, max int, interval time.Duration,
	insert func([]T) error, desc func(T) string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	buf := make([]T, 0, max)
	flush := func() {
		if len(buf) == 0 {
			return
		}
		if err := insert(buf); err != nil {
			gologger.Warning().Msgf("%s批量写入失败(%d条), 降级逐条重试: %v", kind, len(buf), err)
			okN := 0
			for _, r := range buf {
				if e2 := insert([]T{r}); e2 == nil {
					okN++
				} else {
					gologger.Error().Msgf("%s单行丢弃[%s]: %v", kind, desc(r), e2)
				}
			}
			gologger.Warning().Msgf("%s降级重试完成: %d/%d行恢复入库", kind, okN, len(buf))
		}
		buf = buf[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case v := <-ch:
			buf = append(buf, v)
			if len(buf) >= max {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func startConsumer(ctx context.Context, rdb *redis.Client) {
	go consumeQueue(ctx, rdb)
	go batchWriter(ctx, assetChan, "资产", 500, 2*time.Second, insertAssets,
		func(r assetInsert) string { return "task=" + r.taskID + " ip=" + r.ip + " uri=" + r.uri })
	go batchWriter(ctx, vulnChan, "漏洞", 500, 2*time.Second, insertVulns,
		func(r vulnInsert) string { return "task=" + r.taskID + " vuln=" + r.vulnID + " target=" + r.target })
	go batchWriter(ctx, credChan, "凭据", 500, 2*time.Second, insertCreds,
		func(r credInsert) string { return "task=" + r.taskID + " service=" + r.service + " target=" + r.target })
}

// liveTaskSet 批内task_id → 任务是否仍存在。
// 任务删除后消费链路里还可能有尾部结果在飞, 过滤掉避免悬空task_id孤儿行;
// 查询失败时保守放行(宁可偶发孤儿也不丢正常数据)。
func liveTaskSet(ids map[string]bool) map[string]bool {
	arr := make([]string, 0, len(ids))
	for id := range ids {
		arr = append(arr, id)
	}
	live := make(map[string]bool, len(arr))
	rows, err := db.Query(`SELECT id FROM tasks WHERE id = ANY($1)`, pq.Array(arr))
	if err != nil {
		return nil
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			live[id] = true
		}
	}
	return live
}

func insertAssets(rows []assetInsert) error {
	rows = dropOrphans(rows, func(r assetInsert) string { return r.taskID })
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO assets
		(task_id,node_id,asset_type,ip,port,protocol,uri,domain,title,status_code,finger,extra,last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
		ON CONFLICT (task_id,asset_type,ip,port,uri,finger)
		DO UPDATE SET last_seen=now(), title=EXCLUDED.title`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.assetType, r.ip, r.port, r.protocol,
			r.uri, r.domain, r.title, r.statusCode, r.finger, r.extra); err != nil {
			return err
		}
	}
	refreshTaskCounters(tx, rows, func(r assetInsert) string { return r.taskID }, "assets", "found_assets")
	return tx.Commit()
}

func insertVulns(rows []vulnInsert) error {
	rows = dropOrphans(rows, func(r vulnInsert) string { return r.taskID })
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO vulns
		(task_id,node_id,source,vuln_id,severity,target,detail,extra,last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		ON CONFLICT (task_id,source,vuln_id,target,detail)
		DO UPDATE SET last_seen=now()`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.source, r.vulnID, r.severity,
			r.target, r.detail, r.extra); err != nil {
			return err
		}
	}
	refreshTaskCounters(tx, rows, func(r vulnInsert) string { return r.taskID }, "vulns", "found_vulns")
	if err := tx.Commit(); err != nil {
		return err
	}
	notifyVulns(rows) // webhook推送高危(异步防抖)
	return nil
}

func insertCreds(rows []credInsert) error {
	rows = dropOrphans(rows, func(r credInsert) string { return r.taskID })
	if len(rows) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO credentials (task_id,node_id,service,target,detail,last_seen)
		VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (task_id,service,target,detail)
		DO UPDATE SET last_seen=now()`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.service, r.target, r.detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// dropOrphans 过滤任务已删除的行(删除后仍在飞的尾部结果)
func dropOrphans[T any](rows []T, taskID func(T) string) []T {
	ids := make(map[string]bool, len(rows))
	for _, r := range rows {
		ids[taskID(r)] = true
	}
	live := liveTaskSet(ids)
	if live == nil {
		return rows
	}
	out := rows[:0]
	for _, r := range rows {
		if live[taskID(r)] {
			out = append(out, r)
		}
	}
	return out
}

// refreshTaskCounters 回写任务资产/漏洞计数: 只刷本批涉及的task_id,
// 全表UPDATE是O(任务数×行数)每2秒一遍, 大库直接拖垮写入。
// table/column来自调用点硬编码常量, 不接外部输入。
// ⚠️外层UPDATE必须带WHERE id=$1: 漏了会把所有任务行的计数改成本批任务的值
// (2026-09-13线上事故: 全部任务found_assets同显389/662/8737, 组聚合成8737×8=69896)。
func refreshTaskCounters[T any](tx *sql.Tx, rows []T, taskID func(T) string, table, column string) {
	ids := make(map[string]bool, len(rows))
	for _, r := range rows {
		ids[taskID(r)] = true
	}
	for id := range ids {
		_, _ = tx.Exec(fmt.Sprintf(`UPDATE tasks SET %s=(SELECT count(*) FROM %s WHERE task_id=$1) WHERE id=$1`, column, table), id)
	}
}

