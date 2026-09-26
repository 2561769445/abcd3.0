package gopocs

import (
	"abcd/structs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
)

var Mutex = &sync.Mutex{}

// 单线程的
var currentCount = 0

// gopocTargetTimeout 单目标硬顶。各插件内部已有 per-attempt 6s 超时和 len(字典)*6 逃生,
// 但仍存在挂死场景: telnet 库读无 deadline(telnetlib SetReadDeadline 被注释)/SSH 握手后
// session.CombinedOutput 无整体 deadline/Web 中间件爆破对不回包目标阻塞。挂死 goroutine 会
// 让 wg.Wait() 永不返回 → 整个子进程假死(27.149 卡92%两小时零日志事故)。
// watchdog 超时后放弃该目标并释放并发槽, 整批继续; 挂死的插件 goroutine 泄漏(可接受)。
const gopocTargetTimeout = 10 * time.Minute

func AddScan(scantype string, info structs.HostInfo, ch *chan struct{}, wg *sync.WaitGroup) {
	currentCount += 1
	if currentCount%100 == 0 {
		gologger.Info().Msgf("[GoPoc] 当前进度: %v %v [%v/%v]", scantype, info.Host+":"+info.Ports, currentCount, allCount)
	}

	*ch <- struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { <-*ch }() // 槽位释放必须在watchdog收口: 不能等可能挂死的插件goroutine
		Mutex.Lock()
		structs.AddScanNum += 1
		Mutex.Unlock()

		target := info.Host + ":" + info.Ports
		if info.Url != "" {
			target = info.Url
		}
		done := make(chan struct{}, 1)
		go func() {
			ScanFunc(&scantype, &info)
			done <- struct{}{}
		}()
		select {
		case <-done:
		case <-time.After(gopocTargetTimeout):
			gologger.Error().Msgf("[GoPoc] 单目标超时放弃(%v): %v %v — 插件挂死(疑似读无deadline), 释放槽位整批继续", gopocTargetTimeout, scantype, target)
		}
		Mutex.Lock()
		structs.AddScanEnd += 1
		Mutex.Unlock()
	}()
}

func ScanFunc(name *string, info *structs.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Error().Msgf("[-] %v:%v %v error: %v\n", info.Host, info.Ports, name, err)
		}
	}()
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

var allCount = 0

func GoPocsDispatcher(nucleiResults []output.ResultEvent) {
	if len(structs.GlobalIPPortMap) == 0 && len(nucleiResults) == 0 {
		return
	}

	initDic()

	allCount = len(structs.GlobalIPPortMap) + len(nucleiResults)

	var ch = make(chan struct{}, structs.GlobalConfig.GoPocThreads)
	var wg = sync.WaitGroup{}
	gologger.Info().Msg("Golang Poc引擎启动")

	// 各类协议

	for hostPort, protocol := range structs.GlobalIPPortMap {
		t := strings.Split(hostPort, ":")
		host := t[0]
		port := t[1]

		if protocol == "ssh" || port == "22" {
			AddScan("SSH-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "ftp" || port == "21" {
			AddScan("FTP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mysql" || port == "3306" {
			AddScan("Mysql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mssql" || port == "1433" {
			AddScan("Mssql-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "oracle" || port == "1521" {
			AddScan("Oracle-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "mongodb" || port == "27017" {
			AddScan("MongoDB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "rdp" || port == "3389" {
			if structs.GlobalConfig.NoServiceBruteForce {
				continue
			}
			AddScan("RDP-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "redis" || port == "6379" {
			// 有未授权检测
			AddScan("Redis-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "smb" || port == "445" {
			AddScan("SMB-MS17-010",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
			AddScan("SMB-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "postgresql" || port == "5432" {
			AddScan("PostgreSQL-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "telnet" || port == "23" {
			AddScan("Telnet-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "memcached" || port == "11211" {
			AddScan("Memcache-Crack",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "netbios" || port == "445" {
			AddScan("NetBios-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "rpc" {
			AddScan("RPC-GetHostInfo",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "jdwp" {
			AddScan("JDWP-Scan",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}
		if protocol == "adb" || port == "5555" {
			AddScan("ADB-Scan",
				structs.HostInfo{Host: host, Ports: port},
				&ch, &wg)
		}

	}

	// 各类指纹
	//for host, fingers := range structs.GlobalResultMap {
	//
	//}


	// Web 中间件弱口令: Tomcat / WebLogic / JBoss（按站点根去重，避免重复爆破）
	seenRoot := make(map[string]struct{})
	for host, fingers := range structs.GlobalResultMap {
		tomcat, weblogic, jboss, basic := hasWebWeakPasswordFingerprint(fingers)
		// 通用 Basic Auth 针对具体 URL 单独调度
		if basic {
			AddScan("Web-BasicAuth",
				structs.HostInfo{Url: host},
				&ch, &wg)
		}
		if !tomcat && !weblogic && !jboss {
			continue
		}
		// 归一化到站点根（中间件爆破统一基于根路径）
		root := host
		if parsed, err := url.Parse(host); err == nil {
			root = parsed.Scheme + "://" + parsed.Host
		}
		if _, dup := seenRoot[root]; dup {
			continue
		}
		seenRoot[root] = struct{}{}
		AddScan("Web-WeakPassword",
			structs.HostInfo{Url: root},
			&ch, &wg)
	}

	for _, result := range nucleiResults {
		if result.TemplateID == "shiro-detect" {
			AddScan("Shiro-Key-Crack",
				structs.HostInfo{Url: result.Matched},
				&ch, &wg)
		}
	}

	wg.Wait()
}
