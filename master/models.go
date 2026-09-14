package master

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/projectdiscovery/gologger"
)

var db *sql.DB

func initDB(dsn string) error {
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)
	if err = db.Ping(); err != nil {
		return err
	}
	return migrate()
}

func migrate() error {
	// 顺序要求: CREATE INDEX ON x 必须排在 CREATE TABLE x 之后 —— 空库首装时
	// 依赖顺序错了会让migrate整批失败, master进Fatal重启循环(v62在全新机器上踩过)
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			name TEXT, ip TEXT, os TEXT, version TEXT,
			online BOOLEAN DEFAULT FALSE,
			cpu_percent REAL DEFAULT 0, mem_percent REAL DEFAULT 0,
			running_task TEXT DEFAULT '',
			weight INT DEFAULT 10,
			last_heartbeat TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			name TEXT,
			targets TEXT,
			target_count INT DEFAULT 0,
			ports TEXT DEFAULT '',
			options JSONB DEFAULT '{}',
			assigned_node TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			progress INT DEFAULT 0,
			found_assets INT DEFAULT 0,
			found_vulns INT DEFAULT 0,
			cron_expr TEXT DEFAULT '',
			stage TEXT DEFAULT '',
			next_run TIMESTAMPTZ,
			created_by TEXT DEFAULT 'admin',
			created_at TIMESTAMPTZ DEFAULT now(),
			started_at TIMESTAMPTZ,
			finished_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS assets (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT, node_id TEXT,
			asset_type TEXT,           -- ip_alive/port/web/domain/finger...
			ip TEXT DEFAULT '', port TEXT DEFAULT '',
			protocol TEXT DEFAULT '', uri TEXT DEFAULT '',
			domain TEXT DEFAULT '',
			title TEXT DEFAULT '', status_code TEXT DEFAULT '',
			finger TEXT DEFAULT '',     -- 逗号分隔指纹
			extra JSONB DEFAULT '{}',   -- 原始OutputMessage
			tag TEXT DEFAULT '', remark TEXT DEFAULT '',
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(task_id, asset_type, ip, port, uri, finger)
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT,
			node_id TEXT,
			service TEXT,
			target TEXT,
			detail TEXT,
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(task_id,service,target,detail)
		)`,
		`CREATE TABLE IF NOT EXISTS vulns (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT, node_id TEXT,
			source TEXT DEFAULT '',     -- gopoc/nuclei
			vuln_id TEXT DEFAULT '',    -- poc名/CVE
			severity TEXT DEFAULT '',   -- critical/high/medium/low/info
			target TEXT DEFAULT '',     -- ip:port 或 uri
			detail TEXT DEFAULT '',     -- 展示消息/描述
			extra JSONB DEFAULT '{}',
			status TEXT DEFAULT 'open', -- open/fixed/ignored
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(task_id, source, vuln_id, target, detail)
		)`,
		`CREATE TABLE IF NOT EXISTS export_records (
			id BIGSERIAL PRIMARY KEY,
			export_type TEXT, file_path TEXT, fields TEXT,
			row_count INT DEFAULT 0,
			created_by TEXT DEFAULT 'admin',
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		// 索引统一在全部建表之后
		`CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_finger ON assets(finger)`,
		// 任务筛选高频查询(task_id+asset_type WHERE / task_id计数), 50万+行免全表扫
		`CREATE INDEX IF NOT EXISTS idx_assets_task_type ON assets(task_id, asset_type)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_task ON vulns(task_id)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_sev ON vulns(severity)`,
		`CREATE INDEX IF NOT EXISTS idx_credentials_task ON credentials(task_id)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	// 唯一约束带task_id(多任务扫到同一资产/漏洞不互相覆盖串任务)。
	// DROP+ADD成对保证幂等; ADD撞上存量重复行时先去重(保最大id)再重试,
	// 否则启动进崩溃循环 — 去重只在失败时才跑, 常态启动零开销。
	type constraint struct{ table, name, cols, dedup string }
	for _, ct := range []constraint{
		{
			table: "assets", name: "assets_task_unique",
			cols:  "task_id, asset_type, ip, port, uri, finger",
			dedup: `DELETE FROM assets a USING assets b
				WHERE a.id < b.id AND a.task_id IS NOT DISTINCT FROM b.task_id
				AND a.asset_type IS NOT DISTINCT FROM b.asset_type AND a.ip IS NOT DISTINCT FROM b.ip
				AND a.port IS NOT DISTINCT FROM b.port AND a.uri IS NOT DISTINCT FROM b.uri
				AND a.finger IS NOT DISTINCT FROM b.finger`,
		},
		{
			table: "vulns", name: "vulns_task_unique",
			cols:  "task_id, source, vuln_id, target, detail",
			dedup: `DELETE FROM vulns a USING vulns b
				WHERE a.id < b.id AND a.task_id IS NOT DISTINCT FROM b.task_id
				AND a.source IS NOT DISTINCT FROM b.source AND a.vuln_id IS NOT DISTINCT FROM b.vuln_id
				AND a.target IS NOT DISTINCT FROM b.target AND a.detail IS NOT DISTINCT FROM b.detail`,
		},
		{
			table: "credentials", name: "credentials_task_unique",
			cols:  "task_id, service, target, detail",
			dedup: `DELETE FROM credentials a USING credentials b
				WHERE a.id < b.id AND a.task_id IS NOT DISTINCT FROM b.task_id
				AND a.service IS NOT DISTINCT FROM b.service AND a.target IS NOT DISTINCT FROM b.target
				AND a.detail IS NOT DISTINCT FROM b.detail`,
		},
	} {
		db.Exec(`ALTER TABLE ` + ct.table + ` DROP CONSTRAINT IF EXISTS ` + ct.name)
		db.Exec(`ALTER TABLE ` + ct.table + ` DROP CONSTRAINT IF EXISTS ` + legacyConstraintName(ct.table, ct.cols))
		add := `ALTER TABLE ` + ct.table + ` ADD CONSTRAINT ` + ct.name + ` UNIQUE(` + ct.cols + `)`
		if _, err := db.Exec(add); err != nil {
			gologger.Warning().Msgf("%s唯一约束添加失败(存量重复数据?), 去重后重试: %v", ct.table, err)
			if _, derr := db.Exec(ct.dedup); derr != nil {
				return fmt.Errorf("%s去重失败: %w", ct.table, derr)
			}
			if _, aerr := db.Exec(add); aerr != nil {
				return fmt.Errorf("%s唯一约束添加失败: %w", ct.table, aerr)
			}
		}
	}
	return nil
}

// legacyConstraintName PG对内联UNIQUE(...)自动生成的约束名(旧库残留, 需一并DROP)
func legacyConstraintName(table, cols string) string {
	fields := strings.Fields(cols) // 跳过中间空白/换行
	joined := make([]string, 0, len(fields))
	for _, f := range fields {
		joined = append(joined, strings.TrimSuffix(f, ","))
	}
	return table + "_" + strings.Join(joined, "_") + "_key"
}

// TaskRow 任务表行
type TaskRow struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Targets      string     `json:"targets"`
	TargetCount  int        `json:"target_count"`
	Ports        string     `json:"ports"`
	Options      string     `json:"options"`
	AssignedNode string     `json:"assigned_node"`
	Status       string     `json:"status"`
	Progress     int        `json:"progress"`
	FoundAssets  int        `json:"found_assets"`
	FoundVulns   int        `json:"found_vulns"`
	CronExpr     string     `json:"cron_expr"`
	Stage       string     `json:"stage"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    sql.NullTime `json:"started_at"`
	FinishedAt   sql.NullTime `json:"finished_at"`
}

// AssetRow 资产表行
type AssetRow struct {
	ID         int64          `json:"id"`
	TaskID     string         `json:"task_id"`
	NodeID     string         `json:"node_id"`
	AssetType  string         `json:"asset_type"`
	IP         string         `json:"ip"`
	Port       string         `json:"port"`
	Protocol   string         `json:"protocol"`
	URI        string         `json:"uri"`
	Domain     string         `json:"domain"`
	Title      string         `json:"title"`
	StatusCode string         `json:"status_code"`
	Finger     string         `json:"finger"`
	Tag        string         `json:"tag"`
	Remark     string         `json:"remark"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// VulnRow 漏洞表行
type VulnRow struct {
	ID        int64     `json:"id"`
	TaskID    string    `json:"task_id"`
	NodeID    string    `json:"node_id"`
	Source    string    `json:"source"`
	VulnID    string    `json:"vuln_id"`
	Severity  string    `json:"severity"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
