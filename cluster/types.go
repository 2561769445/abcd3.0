package cluster

import "encoding/json"

// 分布式主控-分节点共享协议类型与Redis键名常量

const (
	QueueTasks        = "queue:tasks"   // 公共任务队列(自动分配)
	QueueNodePrefix   = "queue:node:"   // 指定节点队列前缀
	QueueResults      = "queue:results" // 结果上报队列
	QueueResultsRetry = "queue:results:retry"
	HashNodes         = "nodes"          // 节点心跳hash: field=nodeID -> Heartbeat JSON
	ProgressPrefix    = "task:progress:" // 进度hash前缀: key=task:progress:{id}
	CtrlChannelPre    = "ctrl:"          // 控制指令pubsub前缀 ctrl:{nodeID}
	TaskStatePrefix   = "task:state:"    // 任务实时状态 string key
	ExecResultPrefix  = "exec:result:"   // 节点命令执行回执
	FileTmpPrefix     = "nodefile:"      // 文件传输中转(base64)

	// pull模式: 工作队列+进度计数
	QueuePullPrefix = "queue:pull:"     // 工作队列前缀: key=queue:pull:{taskID}[:phase], 元素=单个目标串
	PullTotalPrefix = "task:pull:total:" // 工作总量: key=task:pull:total:{taskID}
	PullDonePrefix  = "task:pull:done:"  // 已完成数: key=task:pull:done:{taskID}(INCR)
	PullLivePrefix  = "task:pull:live:"  // 批内实时进度: 子进程每查完一个关键词INCR, 整批完成时父进程对冲扣回

	// pull模式可靠领取: 节点BRPopLPush原子弹入本节点在途队列, 跑完LRem。
	// 节点掉线时master把在途项按TaskID+Phase搬回公共队列(100%不丢)
	QueuePullProcPrefix = "queue:pullproc:" // key=queue:pullproc:{nodeID}, 元素=PullInflight JSON
)

// QueuePullProcKey 节点pull在途队列键
func QueuePullProcKey(nodeID string) string {
	return QueuePullProcPrefix + nodeID
}

// PullInflight 节点已领取未完成的pull工作项。Work是原始批次串(换行分隔),
// 回搬公共队列时原样RPush, 与dispatch灌入格式完全一致
type PullInflight struct {
	TaskID string `json:"id"`
	Phase  string `json:"phase,omitempty"`
	Work   string `json:"w"`
}

// QueuePullKey pull任务工作队列键: 每阶段独立键(queue:pull:{id}:map/:ports/:deep)。
// 阶段产物回流到下一阶段键 — 老阶段的拉取循环只认自己的键, 回流批不会被本阶段节点
// 按老模式抢跑(共用单键时代: map节点会立即领走自己回流的资产批再跑一遍测绘)。
// phase为空=单阶段老格式(无后缀), 兼容存量。
func QueuePullKey(taskID, phase string) string {
	if phase == "" {
		return QueuePullPrefix + taskID
	}
	return QueuePullPrefix + taskID + ":" + phase
}

// PullPhases 阶段顺序(map→ports→deep), 单阶段任务只走deep或全程一键
var PullPhases = []string{"map", "ports", "deep"}

// ScanOptions 任务携带的扫描参数(完整映射structs.GlobalConfig, 与命令行功能对齐)
type ScanOptions struct {
	// 端口扫描
	PortScanType       string `json:"port_scan_type,omitempty"` // tcp/syn
	TCPPortScanThreads int    `json:"tcp_port_scan_threads,omitempty"`
	SYNPortScanThreads int    `json:"syn_scan_threads,omitempty"`
	NoPortString       string `json:"no_port,omitempty"` // 禁扫端口
	MasscanPath        string `json:"masscan_path,omitempty"`
	PortsThreshold     int    `json:"ports_max_count,omitempty"`
	TCPPortScanTimeout int    `json:"port_scan_timeout,omitempty"`
	AdaptiveTCP        bool   `json:"adaptive_tcp,omitempty"`
	// 主机发现
	SkipHostDiscovery bool `json:"skip_host_discovery,omitempty"`
	NoICMPPing        bool `json:"no_icmp_ping,omitempty"`
	TCPPing           bool `json:"tcp_ping,omitempty"`
	// 协议识别
	GetBannerThreads int `json:"nmap_threads,omitempty"`
	GetBannerTimeout int `json:"nmap_timeout,omitempty"`
	// 子域名
	Subdomain                  bool `json:"subdomain,omitempty"`
	NoSubdomainBruteForce      bool `json:"no_subdomain_brute,omitempty"`
	NoSubFinder                bool `json:"no_subfinder,omitempty"`
	SubdomainBruteForceThreads int  `json:"subdomain_brute_threads,omitempty"`
	AllowLocalAreaDomain       bool `json:"local_domain,omitempty"`
	AllowCDNAssets             bool `json:"allow_cdn,omitempty"`
	NoHostBind                 bool `json:"no_host_bind,omitempty"`
	// Web探针
	WebThreads  int  `json:"web_threads,omitempty"`
	WebTimeout  int  `json:"web_timeout,omitempty"`
	NoDirSearch bool `json:"no_dir_search,omitempty"`
	// 代理
	HTTPProxy string `json:"http_proxy,omitempty"`
	// 空间搜索引擎(配合config/api-config.yaml里的key)
	Hunter         bool `json:"hunter,omitempty"`
	Fofa           bool `json:"fofa,omitempty"`
	Quake          bool `json:"quake,omitempty"`
	HunterPageSize int  `json:"hunter_page_size,omitempty"`
	HunterMaxPage  int  `json:"hunter_max_page,omitempty"`
	FofaMaxCount   int  `json:"fofa_max_count,omitempty"`
	QuakeSize      int  `json:"quake_max_count,omitempty"`
	LowPerception  bool `json:"low_perception_mode,omitempty"`
	OnlyIPPort     bool `json:"only_ip_port,omitempty"`
	// 漏洞探测
	NoPoc             bool   `json:"no_poc,omitempty"`
	NoGolangPoc       bool   `json:"no_golang_poc,omitempty"`
	DisableGeneralPoc bool   `json:"disable_general_poc,omitempty"`
	PocNameForSearch  string `json:"poc_name,omitempty"`
	GoPocThreads      int    `json:"golang_poc_threads,omitempty"`
	ExcludeTags       string `json:"exclude_tags,omitempty"`
	Severities        string `json:"severity,omitempty"`
	NoServiceBrute    bool   `json:"no_brute,omitempty"`
	// 反连
	NoInteractsh    bool   `json:"no_interactsh,omitempty"`
	InteractshURL   string `json:"interactsh_server,omitempty"`
	InteractshToken string `json:"interactsh_token,omitempty"`
	// 爆破凭证
	Password     string `json:"username_password,omitempty"` // 'admin : password'
	PasswordFile string `json:"username_password_file,omitempty"`
	// abcd扩展
	Xray      bool `json:"xray,omitempty"`
	Xscan     bool `json:"xscan,omitempty"`
	Oss       bool `json:"oss,omitempty"`
	Findre    bool `json:"findre,omitempty"`
	JSAPIScan bool `json:"js,omitempty"`
	// abcd扩展: pull模式(目标逐条进Redis工作队列, 节点拉取式认领, 肥瘦自动均衡)
	Mode string `json:"mode,omitempty"` // 空=整任务模式(旧行为); "pull"=拉模式
	// abcd扩展: 两阶段扫描 — 阶段1"ports"(只跑测绘+存活+端口+协议, 产出ip:port),
	// 阶段2"web"(领ip:port批, 跑Web探针+目录+指纹+PoC); 空串=单阶段老行为
	ScanPhase string `json:"scan_phase,omitempty"`
}

// Task 主控下发给节点的扫描任务
type Task struct {
	ID           string      `json:"id"`
	Name         string      `json:"name,omitempty"`
	Targets      []string    `json:"targets"`
	Ports        string      `json:"ports,omitempty"`
	Options      ScanOptions `json:"options"`
	AssignedNode string      `json:"assigned_node,omitempty"` // 空=任意节点可领
	CreatedAt    int64       `json:"created_at"`
}

// ResultEnvelope 节点上报的结果信封(ddout.OutputMessage原样内嵌)
type ResultEnvelope struct {
	TaskID string          `json:"task_id"`
	NodeID string          `json:"node_id"`
	Msg    json.RawMessage `json:"msg"`
}

// Heartbeat 节点心跳
type Heartbeat struct {
	NodeID      string  `json:"node_id"`
	Name        string  `json:"name"`
	IP          string  `json:"ip"`
	OS          string  `json:"os"`
	Version     string  `json:"version"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	RunningTask string  `json:"running_task,omitempty"` // 当前任务ID, 空闲=空
	Ts          int64   `json:"ts"`
}

// CtrlMessage 主控→节点控制指令
type CtrlMessage struct {
	Action  string `json:"action"`            // stop / shutdown / exec
	TaskID  string `json:"task_id,omitempty"` // stop目标任务
	Cmd     string `json:"cmd,omitempty"`     // exec命令/文件路径
	Session string `json:"session,omitempty"` // 终端会话ID(维持cwd)
	ExecID  string `json:"exec_id,omitempty"` // exec回执ID
	Timeout int    `json:"timeout,omitempty"` // exec超时秒
}
