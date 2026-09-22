package engine

import (
	"context"
	"abcd/common"
	"abcd/common/callnuclei"
	"abcd/common/callxray"
	"abcd/common/callxscan"
	"abcd/common/http"
	"abcd/common/ossbucket"
	"abcd/common/report"
	"abcd/common/uncover"
	"abcd/ddout"
	"abcd/gopocs"
	"abcd/lib/ddfinger"
	"abcd/structs"
	"abcd/utils"
	"abcd/utils/cdn"
	httpx "github.com/projectdiscovery/httpx"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"strings"
	"sync"
)

// StageHook 分布式模式: 扫描阶段推进回调(节点用于上报进度)
var StageHook func(stage string)

// ProgressHook 细粒度进度回调: 阶段内实时计数(done/total), 节点上报后master算ETA
// common层经structs.OnStageProgress调用本实现(注入在init, 解耦common↔engine import cycle)
var ProgressHook func(stage string, done, total int64)

func init() {
	structs.OnStageProgress = func(stage string, done, total int64) {
		if ProgressHook != nil {
			ProgressHook(stage, done, total)
		}
	}
}

// totalTargets 本次任务目标总数(阶段百分比计算的统一分母, RunScan入口设置)
var totalTargets int64

var stagePct = map[string]int{
	"start": 1, "collect": 5, "subdomain": 12, "cdn": 18, "alive": 25,
	"portscan": 45, "protocol": 55, "webprobe": 65, "hostbind": 68,
	"dirbrute": 75, "finger": 82, "poc": 92, "done": 100,
}

// ReportProgress 阶段内细粒度进度(无hook时忽略)
func ReportProgress(stage string, done, total int64) {
	if ProgressHook != nil {
		ProgressHook(stage, done, total)
	}
}

// TotalTargets 返回本任务目标总数
func TotalTargets() int64 { return totalTargets }

// SetTotalTargets RunScan入口调用: 供各阶段计算百分比
func SetTotalTargets(n int64) { totalTargets = n }

// ReportStage 上报当前阶段(无hook时忽略)
func ReportStage(stage string) {
	if StageHook != nil {
		StageHook(stage)
	}
}

// SetStageHook 设置阶段回调
func SetStageHook(h func(string)) { StageHook = h }

// SetProgressHook 设置细粒度进度回调
func SetProgressHook(h func(string, int64, int64)) { ProgressHook = h }

// StagePct 阶段对应百分比(未知阶段返回-1)
func StagePct(stage string) int {
	if v, ok := stagePct[stage]; ok {
		return v
	}
	return -1
}

// StageCN 阶段中文名
func StageCN(stage string) string {
	m := map[string]string{
		"start": "启动", "collect": "资产收集", "subdomain": "子域名枚举", "cdn": "CDN识别",
		"alive": "存活探测", "portscan": "端口扫描", "protocol": "协议识别", "webprobe": "Web探针",
		"hostbind": "域名绑定", "dirbrute": "目录探测", "finger": "指纹识别", "poc": "漏洞验证", "done": "完成",
	}
	if v, ok := m[stage]; ok {
		return v
	}
	return stage
}

// RunScan 扫描总入口(从main.workflow导出, 分布式节点/本地共用)
// 各阶段之间检查ctx取消(任务终止/暂停)
func RunScan(ctx context.Context) error {
	var domains []string
	var urls []string
	var domainPort []string
	var ipPort []string
	var ips []string

	ReportStage("start")
	defer ReportStage("done")
	defer gologger.Info().Msg(aurora.BrightGreen("Done!").String())
	defer ddout.FlushOutput()

	if cancelled(ctx) {
		return ctx.Err()
	}
	// v56 两阶段(用户定义): 阶段1"ports"=测绘+存活+端口扫描+协议识别+Web探针(产出活的URL资产);
	// 阶段2"deep"=领取阶段1的URL资产批, 跑目录爆破+指纹+PoC(依赖指纹库的深度工作)
	// 空串=单阶段老行为(全流程一个进程跑完)
	if structs.GlobalConfig.ScanPhase == "deep" {
		return runDeepPhase(ctx)
	}
	// 测绘阶段: 只拉资产并逐条输出(MapAsset), 不在本机继续扫 —
	// 节点收集后把资产批回流浪队列, 由全部节点认领跑后续阶段(测绘大结果不再单机扛)
	if structs.GlobalConfig.ScanPhase == "map" {
		ReportStage("collect")
		searchEngine()
		for _, t := range structs.GlobalConfig.Targets {
			if cancelled(ctx) {
				return ctx.Err()
			}
			if t = strings.TrimSpace(t); t != "" {
				ddout.FormatOutput(ddout.OutputMessage{Type: "MapAsset", URI: t, Show: "[Map] " + t})
			}
		}
		return nil
	}
	// v52: 目标总数=本次任务统一进度分母(端口扫描/Web探针阶段细粒度百分比用)
	SetTotalTargets(int64(len(structs.GlobalConfig.Targets)))
	// pull任务的ports阶段工作项=资产URL批/IP批, 域名已在map阶段测绘过。
	// 再跑searchEngine会把URL当查询串发Hunter(语法错误+3次重试退避), 且3s全局限速令牌
	// 把所有节点子进程串行化: 实测单批5-8分钟×16子进程互相排队, 任务整体拖成小时级。
	if structs.GlobalConfig.Mode != "pull" || structs.GlobalConfig.ScanPhase != "ports" {
		ReportStage("collect")
		searchEngine()
	}

	for _, input := range structs.GlobalConfig.Targets {
		if cancelled(ctx) {
			return ctx.Err()
		}
		inputType := utils.GetInputType(input)
		if inputType == structs.TypeDomain {
			domains = append(domains, input)
			continue
		} else if inputType == structs.TypeDomainPort {
			domainPort = append(domainPort, input)
			continue
		} else if inputType == structs.TypeCIDR {
			for _, ip := range utils.CIDRToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == structs.TypeIPRange {
			for _, ip := range utils.RangerToIP(input) {
				ips = append(ips, ip.String())
			}
		} else if inputType == structs.TypeIP {
			ips = append(ips, input)
		} else if inputType == structs.TypeIPPort {
			ipPort = append(ipPort, input)
		} else if inputType == structs.TypeURL {
			urls = append(urls, input)
		}
	}

	ReportStage("subdomain")
	if structs.GlobalConfig.Subdomain && len(domains) > 0 {
		subdomains := common.GetSubDomain(domains)
		for _, each := range subdomains {
			domains = append(domains, each)
		}
	}
	domains = utils.RemoveDuplicateElement(domains)

	ReportStage("cdn")
	var cdnDomains []string
	var tIPs []string
	if len(domains) > 0 {
		cdnDomains, _, tIPs = cdn.CheckCDNs(domains, structs.GlobalConfig.SubdomainBruteForceThreads)
		for _, each := range tIPs {
			if structs.GlobalConfig.AllowLocalAreaDomain && utils.IsLocalIP(each) {
				continue
			}
			ips = append(ips, each)
		}
	}
	ips = utils.RemoveDuplicateElement(ips)

	// 处理带CDN的域名，只进行https,http的探测，不进行端口扫描
	if structs.GlobalConfig.AllowCDNAssets {
		for _, cd := range cdnDomains {
			urls = append(urls, "http://"+cd)
			urls = append(urls, "https://"+cd)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	// 端口扫描
	if len(ips) > 0 {
		if cancelled(ctx) {
			return ctx.Err()
		}
		ReportStage("alive")
		if !structs.GlobalConfig.SkipHostDiscovery {
			var ICMPAlive []string
			// ICMP 探测存活
			if !structs.GlobalConfig.NoICMPPing {
				ICMPAlive = common.CheckLive(ips, false)
			}

			// TCP 探测存活
			var TCPAlive []string
			if structs.GlobalConfig.TCPPing {
				// 获取没有存活的进行探测
				var uncheck []string
				for _, ip := range ips {
					index := utils.GetItemInArray(ICMPAlive, ip)
					if index == -1 {
						uncheck = append(uncheck, ip)
					}
				}
				gologger.Info().Msg("TCP存活探测")
				common.PortScan = false
				tcpAliveIPPort := common.PortScanTCP(uncheck, "80,443,3389,445,22",
					structs.GlobalConfig.NoPortString,
					structs.GlobalConfig.TCPPortScanTimeout)
				for _, tIPPort := range tcpAliveIPPort {
					t := strings.Split(tIPPort, ":")
					TCPAlive = append(TCPAlive, t[0])
				}
			}

			ips = append(ips, ICMPAlive...)
			ips = append(ips, TCPAlive...)
			ips = utils.RemoveDuplicateElement(ips)
		}
		ReportStage("portscan")
		var tmpIPPort []string

		// 检测Masscan安装
		if structs.GlobalConfig.PortScanType == "syn" {
			if !common.CheckMasScan() {
				gologger.Error().Msg("降级TCP扫描")
				structs.GlobalConfig.PortScanType = "tcp"
			}
		}

		if structs.GlobalConfig.PortScanType == "syn" {
			// 全端口扫描
			tmpIPPort = common.PortScanSYN(ctx, ips)
		} else {
			common.PortScan = true
			tmpIPPort = common.PortScanTCP(ips, structs.GlobalConfig.Ports,
				structs.GlobalConfig.NoPortString,
				structs.GlobalConfig.TCPPortScanTimeout)
		}

		// 单个IP阈值过滤
		tmpIPPort = common.RemoveFirewall(tmpIPPort)

		for _, each := range tmpIPPort {
			ipPort = append(ipPort, each)
		}
		ipPort = utils.RemoveDuplicateElement(ipPort)
	}

	if cancelled(ctx) {
		return ctx.Err()
	}
	ReportStage("protocol")
	getProtocalInput := ipPort
	for _, each := range domainPort {
		getProtocalInput = append(getProtocalInput, each)
	}
	if len(getProtocalInput) > 0 {
		common.GetProtocol(getProtocalInput,
			structs.GlobalConfig.GetBannerThreads,
			structs.GlobalConfig.GetBannerTimeout)
	}

	// 获取http响应
	for hostPort, service := range structs.GlobalIPPortMap {
		if strings.Contains(service, "http") {
			urls = append(urls, "http://"+hostPort)
			urls = append(urls, "https://"+hostPort)
		}
	}
	urls = utils.RemoveDuplicateElement(urls)

	ReportStage("webprobe")
	httpx.CallHTTPx(urls, http.UrlCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout)

	// 非CDN域名 探测域名绑定资产
	// 把只允许域名访问的资产扒拉出来
	ReportStage("hostbind")
	if !structs.GlobalConfig.NoHostBind {
		common.HostBindCheck()
	}

	// v56 阶段1(ports)收工点: 端口+协议+Web探针完成 — 活的URL资产已入库(OutputHook),
	// 目录/指纹/PoC交给阶段2(deep)领取URL清单
	if structs.GlobalConfig.ScanPhase == "ports" {
		gologger.Info().Msgf("阶段1(端口+Web探针)完成: 存活URL已上报, 目录/指纹/PoC由阶段2领取")
		return nil
	}

	var aliveURLs []string
	for rootURL, _ := range structs.GlobalURLMap {
		aliveURLs = append(aliveURLs, rootURL)
	}

	// 模糊搜索Yaml Poc直接打
	if structs.GlobalConfig.PocNameForSearch != "" {
		gologger.AuditTimeLogger("模糊搜索Poc: %v", structs.GlobalConfig.PocNameForSearch)
		TargetAndPocsName := make(map[string][]string)
		for _, url := range aliveURLs {
			TargetAndPocsName[url] = []string{}
		}
		report.GenerateHTMLReportHeader()

		param := callnuclei.NucleiParams{
			TargetAndPocsName: TargetAndPocsName,
			Proxy:             structs.GlobalConfig.HTTPProxy,
			CallBack:          report.AddResultByResultEvent,
			NameForSearch:     structs.GlobalConfig.PocNameForSearch,
			NoInteractsh:      structs.GlobalConfig.NoInteractsh,
			Fs:                structs.GlobalEmbedPocs,
			NP:                structs.GlobalConfig.NucleiTemplate,
			ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
			Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
			InteractshServer:  structs.GlobalConfig.InteractshURL,
			InteractshToken:   structs.GlobalConfig.InteractshToken,
		}
		callnuclei.CallNuclei(param)
		report.GenerateHTMLReportFooter()
		utils.DeleteReportWithNoResult()
		return nil
	}

	if cancelled(ctx) {
		return ctx.Err()
	}

	// 目录爆破
	ReportStage("dirbrute")
	if !structs.GlobalConfig.NoDirSearch {
		var checkURLs []string
		for path, _ := range structs.DirDB {
			for _, u := range aliveURLs {
				Url := ""
				if u[len(u)-1:] == "/" && path[0:1] == "/" {
					Url = u[:len(u)-1] + path
				} else {
					Url = u + path
				}
				checkURLs = append(checkURLs, Url)
			}
		}
		checkURLs = utils.RemoveDuplicateElement(checkURLs)
		gologger.Info().Msg("开始主动指纹探测")
		httpx.DirBrute(checkURLs,
			http.DirBruteCallBack,
			structs.GlobalConfig.HTTPProxy,
			structs.GlobalConfig.WebThreads,
			structs.GlobalConfig.WebTimeout)
		gologger.AuditTimeLogger("主动指纹探测结束")
	}

	ReportStage("finger")
ddfinger.FingerprintIdentification()

	// ---- abcd 集成功能 ----
	// findre 指纹复核
	http.FindreScanAll()
	// JS 接口/敏感信息扫描
	common.JSAPIScanAll()
	// 云存储桶未授权检测
	ossbucket.DetectBuckets()

	if structs.GlobalConfig.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return nil
	}

	if cancelled(ctx) {
		return ctx.Err()
	}

	ReportStage("poc")
	// 生成报告头部
	report.GenerateHTMLReportHeader()

	// 调用Nuclei
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := http.GetPocs(structs.WorkFlowDB)
	if count > 0 {
		param := callnuclei.NucleiParams{
			TargetAndPocsName: TargetAndPocsName,
			Proxy:             structs.GlobalConfig.HTTPProxy,
			CallBack:          report.AddResultByResultEvent,
			NameForSearch:     "",
			NoInteractsh:      structs.GlobalConfig.NoInteractsh,
			Fs:                structs.GlobalEmbedPocs,
			NP:                structs.GlobalConfig.NucleiTemplate,
			ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
			Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
			InteractshServer:  structs.GlobalConfig.InteractshURL,
			InteractshToken:   structs.GlobalConfig.InteractshToken,
		}

		nucleiResults = callnuclei.CallNuclei(param)

	}

	// GoPoc引擎
	if !structs.GlobalConfig.NoGolangPoc {
		gopocs.GoPocsDispatcher(nucleiResults)
	}

	// ---- abcd: 外部扫描器联动 ----
	if structs.GlobalConfig.Xray {
		callxray.CallXray()
	}
	if structs.GlobalConfig.Xscan {
		callxscan.CallXscan()
	}

	// 没有漏洞结果，删除生成的HTML
	report.GenerateHTMLReportFooter()
	utils.DeleteReportWithNoResult()

	return nil
}

// runDeepPhase v56阶段2(deep): 领取阶段1的URL资产批(工作项=逗号分隔的http(s)://ip:port串),
// 跑目录爆破+主动指纹+指纹识别+findre/JS/OSS+Nuclei+GoPoc。目标已活, 无需端口/存活。
func runDeepPhase(ctx context.Context) error {
	// 目标串即URL批(阶段1产出的http://ip:port), 直接进GlobalURLMap流程
	urls := utils.RemoveDuplicateElement(structs.GlobalConfig.Targets)
	gologger.Info().Msgf("阶段2(deep): 领取 %d 个URL资产, 跑目录/指纹/PoC", len(urls))
	SetTotalTargets(int64(len(urls)))

	// URL灌入Web探针回调(注册进GlobalURLMap, 指纹/目录/PoC都以它为输入源)
	httpx.CallHTTPx(urls, http.UrlCallBack,
		structs.GlobalConfig.HTTPProxy,
		structs.GlobalConfig.WebThreads,
		structs.GlobalConfig.WebTimeout)

	var aliveURLs []string
	for rootURL := range structs.GlobalURLMap {
		aliveURLs = append(aliveURLs, rootURL)
	}
	if len(aliveURLs) == 0 {
		// 探针全死(阶段1到阶段2间隔内目标下线): 不算失败, 收工
		gologger.Info().Msg("阶段2: 探针后无存活URL, 收工")
		return nil
	}

	// 目录爆破
	ReportStage("dirbrute")
	if !structs.GlobalConfig.NoDirSearch {
		var checkURLs []string
		for path := range structs.DirDB {
			for _, u := range aliveURLs {
				Url := ""
				if u[len(u)-1:] == "/" && path[0:1] == "/" {
					Url = u[:len(u)-1] + path
				} else {
					Url = u + path
				}
				checkURLs = append(checkURLs, Url)
			}
		}
		checkURLs = utils.RemoveDuplicateElement(checkURLs)
		gologger.Info().Msg("开始主动指纹探测")
		httpx.DirBrute(checkURLs,
			http.DirBruteCallBack,
			structs.GlobalConfig.HTTPProxy,
			structs.GlobalConfig.WebThreads,
			structs.GlobalConfig.WebTimeout)
	}

	// 指纹识别+abcd扩展
	ReportStage("finger")
	ddfinger.FingerprintIdentification()
	http.FindreScanAll()
	common.JSAPIScanAll()
	ossbucket.DetectBuckets()

	if structs.GlobalConfig.NoPoc {
		gologger.Info().Msg("跳过漏洞探测")
		return nil
	}
	if cancelled(ctx) {
		return ctx.Err()
	}

	ReportStage("poc")
	report.GenerateHTMLReportHeader()
	var nucleiResults []output.ResultEvent
	TargetAndPocsName, count := http.GetPocs(structs.WorkFlowDB)
	if count > 0 {
		param := callnuclei.NucleiParams{
			TargetAndPocsName: TargetAndPocsName,
			Proxy:             structs.GlobalConfig.HTTPProxy,
			CallBack:          report.AddResultByResultEvent,
			NoInteractsh:      structs.GlobalConfig.NoInteractsh,
			Fs:                structs.GlobalEmbedPocs,
			NP:                structs.GlobalConfig.NucleiTemplate,
			ExcludeTags:       strings.Split(structs.GlobalConfig.ExcludeTags, ","),
			Severities:        strings.Split(structs.GlobalConfig.Severities, ","),
			InteractshServer:  structs.GlobalConfig.InteractshURL,
			InteractshToken:   structs.GlobalConfig.InteractshToken,
		}
		nucleiResults = callnuclei.CallNuclei(param)
	}
	if !structs.GlobalConfig.NoGolangPoc {
		gopocs.GoPocsDispatcher(nucleiResults)
	}
	if structs.GlobalConfig.Xray {
		callxray.CallXray()
	}
	if structs.GlobalConfig.Xscan {
		callxscan.CallXscan()
	}
	report.GenerateHTMLReportFooter()
	utils.DeleteReportWithNoResult()
	return nil
}

func cancelled(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func searchEngine() {
	// v70 Fofa+Quake双开(无Hunter): 两引擎并行查同一目标集, 结果合并去重。
	// 这是map引擎分流后域名/IP测绘的主路径 — fofa/quake各自独立限速,
	// 吞吐=两引擎之和, 不挤Hunter的3s全局限速闸。必须放在下方互斥分支之前,
	// 否则被"Fofa&&!Hunter"短路成只跑fofa(quake闲置)。
	if structs.GlobalConfig.Fofa && structs.GlobalConfig.Quake && !structs.GlobalConfig.Hunter {
		var wg sync.WaitGroup
		var mu sync.Mutex
		merged := make([]string, 0, 256)
		for _, search := range []func([]string) []string{
			uncover.FOFASearch, uncover.QuakeSearch,
		} {
			wg.Add(1)
			go func(f func([]string) []string) {
				defer wg.Done()
				res := f(structs.GlobalConfig.Targets)
				mu.Lock()
				merged = append(merged, res...)
				mu.Unlock()
			}(search)
		}
		wg.Wait()
		structs.GlobalConfig.Targets = utils.RemoveDuplicateElement(merged)
		return
	}
	// 从Hunter中获取资产
	if structs.GlobalConfig.Hunter && !structs.GlobalConfig.Fofa {
		structs.GlobalConfig.Targets, _ = uncover.HunterSearch(structs.GlobalConfig.Targets)
		return
	}
	// 从Fofa中获取资产
	if structs.GlobalConfig.Fofa && !structs.GlobalConfig.Hunter {
		structs.GlobalConfig.Targets = uncover.FOFASearch(structs.GlobalConfig.Targets)
		return
	}
	// 从Hunter中获取资产后使用Fofa进行端口补充。
	if structs.GlobalConfig.Fofa && structs.GlobalConfig.Hunter {
		targets, tIPs := uncover.HunterSearch(structs.GlobalConfig.Targets)
		var querys []string
		for _, i := range tIPs {
			querys = append(querys, "ip=\""+i+"\"")
		}
		querys = utils.RemoveDuplicateElement(querys)
		structs.GlobalConfig.Targets = uncover.FOFASearch(querys)
		structs.GlobalConfig.Targets = append(structs.GlobalConfig.Targets, targets...)
		structs.GlobalConfig.Targets = utils.RemoveDuplicateElement(structs.GlobalConfig.Targets)
		return
	}
	// 从Quake获取资产
	if structs.GlobalConfig.Quake {
		structs.GlobalConfig.Targets = uncover.QuakeSearch(structs.GlobalConfig.Targets)
	}

}
