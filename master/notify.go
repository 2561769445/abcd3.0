package master

import (
	"context"
	"sync"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// ---------- Webhook通知(企业微信/钉钉) ----------
// 配置: ABCD_WEBHOOK环境变量 = 机器人webhook地址; 留空=关闭推送
// 触发: ①Critical/High新漏洞(10分钟防抖合并) ②任务完成

var (
	webhookMu    sync.RWMutex
	curWebhook   = os.Getenv("ABCD_WEBHOOK") // 启动默认env, 运行时可由设置页热改
	notifyWindow = map[string]time.Time{}    // vulnID|target → 上次推送时间(防抖)
	doneNotified = map[string]bool{}         // taskID → 已推完成通知
)

// GetWebhook / SetWebhook 线程安全的运行时配置
func GetWebhook() string {
	webhookMu.RLock()
	defer webhookMu.RUnlock()
	return curWebhook
}
func SetWebhook(u string) {
	webhookMu.Lock()
	curWebhook = u
	webhookMu.Unlock()
}

func pushWebhook(title, content string) {
	hook := GetWebhook()
	if hook == "" {
		return
	}
	payload := fmt.Sprintf(`{"msgtype":"markdown","markdown":{"content":"# %s\n%s"}}`, title, content)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", hook, strings.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		gologger.Warning().Msgf("webhook推送失败: %v", err)
		return
	}
	resp.Body.Close()
}

// notifyVulns 高危漏洞推送: consumer批量写库后调用, 同漏洞10分钟内不重复
func notifyVulns(rows []vulnInsert) {
	if GetWebhook() == "" {
		return
	}
	var lines []string
	now := time.Now()
	notifyMutex.Lock()
	for _, r := range rows {
		if r.severity != "critical" && r.severity != "high" {
			continue
		}
		key := r.vulnID + "|" + r.target
		if t, ok := notifyWindow[key]; ok && now.Sub(t) < 10*time.Minute {
			continue
		}
		notifyWindow[key] = now
		lines = append(lines, fmt.Sprintf("> **[%s]** %s\n> 目标: %s", r.severity, r.vulnID, r.target))
		if len(lines) >= 8 {
			break // 单条消息上限, 余量下轮推
		}
	}
	notifyMutex.Unlock()
	if len(lines) > 0 {
		go pushWebhook(fmt.Sprintf("ABCD高危漏洞 +%d", len(lines)), strings.Join(lines, "\n\n"))
	}
}

// notifyTaskDone 任务完成通知: scheduler检测到done状态翻转时调用一次
func notifyTaskDone(taskID string) {
	if GetWebhook() == "" {
		return
	}
	notifyMutex.Lock()
	sent := doneNotified[taskID]
	doneNotified[taskID] = true
	notifyMutex.Unlock()
	if sent {
		return
	}
	var name string
	var assets, vulns int
	if err := db.QueryRow(`SELECT name,found_assets,found_vulns FROM tasks WHERE id=$1`, taskID).Scan(&name, &assets, &vulns); err != nil {
		return
	}
	go pushWebhook("任务完成", fmt.Sprintf("> **%s**\n> 资产 %d · 漏洞 %d\n> %s", name, assets, vulns, taskID))
}

// notifyMutex 保护notifyWindow/doneNotified(consumer批量线程写, janitor清理线程删)
var notifyMutex sync.Mutex

// ForgetTask 任务终态/删除时调用: doneNotified条目只在防重窗口内有意义, 留着即泄漏
func ForgetTask(taskID string) {
	notifyMutex.Lock()
	delete(doneNotified, taskID)
	notifyMutex.Unlock()
}

// StartNotifyJanitor 周期清理过期的防抖窗口条目(超30分钟未再触发的漏洞key),
// 否则notifyWindow按"漏洞×目标"组合无限增长。
func StartNotifyJanitor(ctx context.Context) {
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now()
				notifyMutex.Lock()
				for k, ts := range notifyWindow {
					if now.Sub(ts) > 30*time.Minute {
						delete(notifyWindow, k)
					}
				}
				notifyMutex.Unlock()
			}
		}
	}()
}
