// portmux: 单端口协议分流器
// 监听对外端口, 嗅探首行: HTTP请求行(方法+路径+HTTP/x.x) → HTTP后端; 其余(Redis RESP/inline) → Redis后端。
//
// 判定依据是完整首行而非首包前缀:
//   - TCP分片: "GE"/"T / ..." 两次Read拼起来才是完整请求行
//   - HTTP/2: 连接前导 "PRI * HTTP/2.0" 不在常见方法表里, 按行首段+版本段识别
//   - Redis的GET命令("GET foo\r\n")与HTTP GET同名, 但没有HTTP/x版本尾段 → 转Redis
package main

import (
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	listenAddr = getenv("MUX_LISTEN", ":6379")
	httpAddr   = getenv("MUX_HTTP", "127.0.0.1:8080")
	redisAddr  = getenv("MUX_REDIS", "127.0.0.1:6390")
	idleLimit  = 10 * time.Minute // 双向空闲上限, 到期断开防goroutine+fd泄漏
)

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true, "PRI": true,
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("portmux %s -> HTTP:%s Redis:%s", listenAddr, httpAddr, redisAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	line, ok := sniffFirstLine(c)
	if !ok {
		return
	}
	addr := route(line)
	up, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer up.Close()
	first := line
	if addr == httpAddr {
		first = injectClientIP(line, c.RemoteAddr())
	}
	if _, err := up.Write(first); err != nil { // 首行(含已读到的多余字节, HTTP方向已注入客户端IP头)转发
		return
	}
	done := make(chan struct{}, 2)
	go pipe(up, c, done)
	go pipe(c, up, done)
	<-done
}

// injectClientIP HTTP方向在请求行后注入X-Forwarded-For/X-Real-IP:
// portmux是L4透传, 后端看到的源IP恒为回环, per-IP限速不可用(N12遗留)。
// 注入位置在客户端自带同名头之前(HTTP语义Header.Get取首值), 客户端无法伪造排位。
// PRI(HTTP/2明文前导)跳过 — 其后紧跟二进制SETTINGS帧, 注入文本会破坏帧协议。
func injectClientIP(buf []byte, raddr net.Addr) []byte {
	line := string(buf)
	if i := indexOfCRLF(buf); i >= 0 {
		line = line[:i]
	}
	if parts := strings.Fields(line); len(parts) > 0 && parts[0] == "PRI" {
		return buf
	}
	ip, _, err := net.SplitHostPort(raddr.String())
	if err != nil {
		ip = raddr.String()
	}
	idx := indexOfCRLF(buf)
	if idx < 0 {
		return buf // sniff已保证有完整首行, 防御性兜底
	}
	inj := []byte("X-Forwarded-For: " + ip + "\r\nX-Real-IP: " + ip + "\r\n")
	out := make([]byte, 0, len(buf)+len(inj))
	out = append(out, buf[:idx+2]...)
	out = append(out, inj...)
	out = append(out, buf[idx+2:]...)
	return out
}

// sniffFirstLine 循环读直到凑齐首行(见\r\n)或读满缓冲。
// 返回值含首行及其后已读到的字节(可能多读, 调用方需原样转发)。
func sniffFirstLine(c net.Conn) ([]byte, bool) {
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	for len(buf) < cap(buf) {
		if idx := indexOfCRLF(buf); idx >= 0 {
			return buf, true
		}
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if idx := indexOfCRLF(buf); idx >= 0 {
			return buf, true
		}
		if err != nil {
			return nil, false // 超时/对端关闭/读满仍无完整行
		}
	}
	return nil, false
}

func indexOfCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}

// route 首行 → 后端地址。
// HTTP请求行三段式: "METHOD SP target SP HTTP/x.y", 方法在表内且末段以HTTP/开头才认定HTTP;
// 其余(带内联命令/RESP数组/半截垃圾)一律Redis。
func route(buf []byte) string {
	line := string(buf)
	if i := indexOfCRLF(buf); i >= 0 {
		line = line[:i]
	}
	parts := strings.Fields(line)
	if len(parts) == 3 && httpMethods[parts[0]] && strings.HasPrefix(parts[2], "HTTP/") {
		return httpAddr
	}
	return redisAddr
}

// pipe 双向透传, 每次读到数据刷新空闲deadline: 长连接保活, 死连接到期回收
func pipe(dst, src net.Conn, done chan struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 32*1024)
	for {
		src.SetReadDeadline(time.Now().Add(idleLimit))
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
