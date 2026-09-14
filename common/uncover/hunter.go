package uncover

import (
	"abcd/ddout"
	"abcd/structs"
	"abcd/utils"
	"abcd/utils/cdn"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/hashes"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type HunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
	IsWeb    string `json:"is_web"`
	City     string `json:"city"`
	Company  string `json:"company"`
	Code     int    `json:"status_code"`
	Title    string `json:"web_title"`
	Country  string `json:"country"`
	Banner   string `json:"banner"`
}

type hunterData struct {
	InfoArr   []infoArr `json:"arr"`
	Total     int       `json:"total"`
	RestQuota string    `json:"rest_quota"`
}

func getHunterKeys() []string {
	var apiKeys []string
	f, err := os.Open(structs.GlobalConfig.APIConfigFilePath)
	if err != nil {
		gologger.Error().Msgf("打开API Key配置文件 %v 失败", structs.GlobalConfig.APIConfigFilePath)
		return []string{}
	}
	defer f.Close()

	sourceApiKeysMap := map[string][]string{}
	err = yaml.NewDecoder(f).Decode(sourceApiKeysMap)
	for _, source := range passive.AllSources {
		sourceName := strings.ToLower(source.Name())
		if sourceName == "hunter" {
			apiKeys = sourceApiKeysMap[sourceName]
			break
		}
	}
	if len(apiKeys) == 0 {
		gologger.Error().Msg("未配置Hunter Key(主控Web系统设置页可配), 跳过Hunter测绘")
		return []string{}
	}

	return apiKeys
}

// hunterRateKey Redis全局限速键(多节点共用一个Hunter key时全局节流, 根除429互踩)
var hunterRateKey = "ratelimit:hunter"

// hunterIntervalMs 全局最小API间隔毫秒(ABCD_HUNTER_INTERVAL_MS环境变量可调, 默认3000)
func hunterIntervalMs() int64 {
	if v := os.Getenv("ABCD_HUNTER_INTERVAL_MS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 3000
}

var hunterRdb *redis.Client

// HunterProgressHook 每完成一个关键词查询后的回调(节点注入: 写批内实时进度)
var HunterProgressHook func()

// hunterQuotaExhausted 积分熔断标志(本节点进程内, 当日API全废不再浪费调用)
var hunterQuotaExhausted atomic.Bool

// SetHunterRedis 注入Redis客户端(节点启动时调用; nil=限速退化为直通)
func SetHunterRedis(c *redis.Client) { hunterRdb = c }

// hunterToken Redis令牌限速: SETNX PX=interval 抢到令牌才放行API调用。
// 抢不到→睡150ms重试; Redis故障→fail-open直接放行(不因限速器挂掉卡死扫描)。
func hunterToken() {
	if hunterRdb == nil {
		return
	}
	interval := hunterIntervalMs()
	for i := 0; i < 200; i++ { // 上限保护: 最多等60s
		ok, err := hunterRdb.SetNX(context.Background(), hunterRateKey, 1, time.Duration(interval)*time.Millisecond).Result()
		if err != nil {
			return // Redis异常: fail-open
		}
		if ok {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
}

// SearchHunter 从Hunter中搜索目标
func SearchHunterCore(keyword string, pageSize int, maxQueryPage int) ([]string, []string) {
	// 积分熔断: 本节点已确认当日积分耗尽, 后续关键词直接跳过(不用再烧API调用去确认)
	if hunterQuotaExhausted.Load() {
		gologger.Warning().Msgf("[Hunter] 积分熔断中, 跳过: %s", keyword)
		return nil, nil
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://hunter.qianxin.com/openApi/search"
	keys := getHunterKeys()
	if len(keys) == 0 {
		return nil, nil
	}
	randKey := keys[rand.Intn(len(keys))]

	page := 1
	currentQueryCount := 0
	rateLimited := 0 // 429有界重试计数
	netFail := 0     // v57: 网络/解析错误有界重试计数

	// Hunter API要求 page_size>=10(否则400"页大小不合法"), 页数>=1, 兜底clamp防前端乱填
	if pageSize < 10 {
		pageSize = 10
	}
	if maxQueryPage < 1 {
		maxQueryPage = 1
	}

	var results []string
	var ipResult []string
	for page <= maxQueryPage {
		// 全局令牌限速: 多节点共用key时集群级≥interval一次, 根除429互踩
		hunterToken()
		req, err := retryablehttp.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			gologger.Error().Msgf("[Hunter] API请求构建失败: %v", err)
			return results, ipResult
		}
		unc := keyword
		search := base64.URLEncoding.EncodeToString([]byte(unc))
		q := req.URL.Query()
		q.Add("search", search)
		q.Add("api-key", randKey)
		q.Add("page", fmt.Sprintf("%d", page))
		q.Add("page_size", fmt.Sprintf("%d", pageSize))
		q.Add("is_web", "3")
		req.URL.RawQuery = q.Encode()

		resp, errDo := client.Do(req)
		if errDo != nil {
			// v57: 网络错误有界重试(3次) — 原无界continue在网络不可达时死循环挂死子进程
			netFail++
			gologger.Error().Msgf("[Hunter] %s 查询失败(%d/3): %v", keyword, netFail, errDo.Error())
			if netFail >= 3 {
				return results, ipResult
			}
			time.Sleep(time.Second * 3)
			continue
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			netFail++
			gologger.Error().Msgf("Hunter 响应Body读取失败(%d/3): %v", netFail, err.Error())
			if netFail >= 3 {
				return results, ipResult
			}
			time.Sleep(time.Second * 3)
			continue
		}

		var responseJson HunterResp
		if err = json.Unmarshal(data, &responseJson); err != nil {
			netFail++
			gologger.Error().Msgf("Hunter JSON解析失败(%d/3): %v", netFail, err.Error())
			if netFail >= 3 {
				return results, ipResult
			}
			time.Sleep(time.Second * 3)
			continue
		}

		if responseJson.Code != 200 {
			// 积分耗尽: 全集群当日已废, 立即熔断放弃(原版sleep死循环重试=节点假死到天亮)
			if strings.Contains(responseJson.Message, "今日免费积分已用") ||
				strings.Contains(responseJson.Message, "积分不足") ||
				strings.Contains(responseJson.Message, "积分已用完") {
				gologger.Error().Msgf("[Hunter] 积分已耗尽(%s), 熔断跳过后续所有Hunter查询", responseJson.Message)
				hunterQuotaExhausted.Store(true)
				return results, ipResult
			}
			// 429限流: 令牌已保证集群级间隔, 这里只会偶发 — 有界重试3次后放弃
			if strings.Contains(responseJson.Message, "请求太多啦") || strings.Contains(responseJson.Message, "稍后再试") {
				rateLimited++
				gologger.Warning().Msgf("[Hunter] 限流(%d/3): %s", rateLimited, keyword)
				if rateLimited >= 3 {
					gologger.Error().Msgf("[Hunter] 连续限流3次, 放弃关键词: %s", keyword)
					return results, ipResult
				}
				time.Sleep(time.Duration(5*rateLimited) * time.Second)
				continue
			}
			gologger.Error().Msgf("[Hunter] %s 搜索失败！Error:%s", keyword, responseJson.Message)
			return results, ipResult
		}

		if responseJson.Data.Total == 0 {
			gologger.Error().Msgf("[Hunter] %s 无结果。", keyword)
			time.Sleep(time.Second * 3)
			return results, ipResult
		}

		// 做一个域名缓存，避免重复dns请求
		domainCDNMap := make(map[string]bool)
		var domainList []string

		for _, v := range responseJson.Data.InfoArr {
			domainList = append(domainList, v.Domain)
		}

		domainList = utils.RemoveDuplicateElement(domainList)
		if len(domainList) != 0 {
			gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(domainList))
		}
		cdnDomains, normalDomains, _ := cdn.CheckCDNs(domainList, structs.GlobalConfig.SubdomainBruteForceThreads)
		for _, d := range cdnDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				domainCDNMap[d] = true
			}
		}
		for _, d := range normalDomains {
			_, ok := domainCDNMap[d]
			if !ok {
				domainCDNMap[d] = false
			}
		}

		for _, v := range responseJson.Data.InfoArr {
			isCDN := false
			t, ok := domainCDNMap[v.Domain]
			if ok {
				isCDN = t
			}
			if !isCDN {
				AddIPDomainMap(v.IP, v.Domain)
			}
			if v.IsWeb == "是" {
				if structs.GlobalConfig.LowPerceptionMode {
					rootURL := fmt.Sprintf("%s://%s:%d", v.Protocol, v.IP, v.Port)

					structs.GlobalURLMapLock.Lock()
					_, rootURLOK := structs.GlobalURLMap[rootURL]
					structs.GlobalURLMapLock.Unlock()
					if !rootURLOK {
						responseCode, header, body, server, contentType, contentLen := utils.ExtractResponse(v.Banner)

						md5 := hashes.Md5([]byte(body))
						headerMd5 := hashes.Md5([]byte(header))
						_ = structs.GlobalHttpBodyHMap.Set(md5, []byte(body))
						_ = structs.GlobalHttpHeaderHMap.Set(headerMd5, []byte(header))

						l, e := strconv.Atoi(contentLen)
						if e != nil {
							l = 0
						}

						rspc, re := strconv.Atoi(responseCode)
						if re != nil {
							rspc = 0
						}

						webPath := structs.UrlPathEntity{
							Hash:             md5,
							Title:            v.Title,
							StatusCode:       rspc,
							ContentType:      contentType,
							Server:           server,
							ContentLength:    l,
							HeaderHashString: headerMd5,
							IconHash:         "", // hunter未提供hash
						}

						urlE := structs.URLEntity{
							IP:       v.IP,
							Port:     v.Port,
							WebPaths: nil,
							Cert:     "", // hunter未提供证书信息
						}

						urlE.WebPaths = make(map[string]structs.UrlPathEntity)
						urlE.WebPaths["/"] = webPath

						structs.GlobalURLMapLock.Lock()
						structs.GlobalURLMap[rootURL] = urlE
						structs.GlobalURLMapLock.Unlock()
					}
				} else { // 正常模式
					p := ""
					if structs.GlobalConfig.OnlyIPPort && !isCDN {
						p = fmt.Sprintf("%s://%s:%d", v.Protocol, v.IP, v.Port)
					} else {
						p = v.URL
					}
					if utils.GetItemInArray(results, p) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							results = append(results, p)
							// gologger.Silent().Msgf("[Hunter] [%d] %s [%s] [%s] [%s]", v.Code, p, v.Title, v.City, v.Company)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:     "Hunter",
								IP:       v.IP,
								IPs:      nil,
								Port:     strconv.Itoa(v.Port),
								Protocol: v.Protocol,
								Web: ddout.WebInfo{
									Title:  v.Title,
									Status: strconv.Itoa(v.Code),
								},
								Finger:        nil,
								Domain:        v.Domain,
								GoPoc:         ddout.GoPocsResultType{},
								URI:           p,
								City:          v.City,
								AdditionalMsg: v.Company,
							})
						}
					}
				}
			} else {
				if structs.GlobalConfig.LowPerceptionMode {
					hostPort := fmt.Sprintf("%s:%d", v.IP, v.Port)
					structs.GlobalIPPortMapLock.Lock()
					_, ok := structs.GlobalIPPortMap[hostPort]
					structs.GlobalIPPortMapLock.Unlock()
					if !ok {
						structs.GlobalBannerHMap.Set(hostPort, []byte(v.Banner))
						structs.GlobalIPPortMapLock.Lock()
						structs.GlobalIPPortMap[hostPort] = v.Protocol
						structs.GlobalIPPortMapLock.Unlock()
					}
				} else {
					results = append(results, fmt.Sprintf("%s:%v", v.IP, v.Port))

					p := fmt.Sprintf("%s:%d", v.IP, v.Port)
					if utils.GetItemInArray(results, p) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							results = append(results, p)
							// gologger.Silent().Msgf("[Hunter] %s://%s:%d", v.Protocol, v.IP, v.Port)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Hunter",
								IP:            v.IP,
								IPs:           nil,
								Port:          strconv.Itoa(v.Port),
								Protocol:      v.Protocol,
								Web:           ddout.WebInfo{},
								Finger:        nil,
								Domain:        v.Domain,
								GoPoc:         ddout.GoPocsResultType{},
								URI:           "",
								City:          v.City,
								AdditionalMsg: v.Company,
							})
						}
					}
				}
			}
			if !isCDN {
				ipResult = append(ipResult, v.IP)
			}
		}

		currentQueryCount += len(responseJson.Data.InfoArr)
		gologger.Info().Msgf("[Hunter] [%s] 当前第 [%d] 页 查询进度: %d/%d %v", keyword, page, currentQueryCount,
			responseJson.Data.Total, responseJson.Data.RestQuota)

		if currentQueryCount >= responseJson.Data.Total {
			return results, ipResult
		}

		page += 1

		// 避免请求过于频繁
		time.Sleep(time.Second * 3)

	}
	return results, ipResult
}

func HunterSearch(keywords []string) ([]string, []string) {
	gologger.Info().Msgf("准备从 Hunter 获取数据")
	gologger.AuditTimeLogger("准备从 Hunter 获取数据")
	var results []string
	var ipResults []string
	for _, keyword := range keywords {
		result, ipResult := SearchHunterCore(keyword,
			structs.GlobalConfig.HunterPageSize,
			structs.GlobalConfig.HunterMaxPageCount)
		results = append(results, result...)
		ipResults = append(ipResults, ipResult...)
		// 批内实时进度: 每查完一个关键词回调一次(pull任务进度条按查询粒度动, 不再整批跳变)
		if HunterProgressHook != nil {
			HunterProgressHook()
		}
	}
	return utils.RemoveDuplicateElement(results), utils.RemoveDuplicateElement(ipResults)
}
