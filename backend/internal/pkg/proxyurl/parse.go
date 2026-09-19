// Package proxyurl 提供代理 URL 的统一验证（fail-fast，无效代理不回退直连）
//
// 所有需要解析代理 URL 的地方必须通过此包的 Parse 函数。
// 直接使用 url.Parse 处理代理 URL 是被禁止的。
// 这确保了 fail-fast 行为：无效代理配置在创建时立即失败，
// 而不是在运行时静默回退到直连（产生 IP 关联风险）。
package proxyurl

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// allowedSchemes 代理协议白名单
var allowedSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

// Parse 解析并验证代理 URL。
//
// 语义:
//   - 空字符串 → ("", nil, nil)，表示直连
//   - 非空且有效 → (trimmed, *url.URL, nil)
//   - 非空但无效 → ("", nil, error)，fail-fast 不回退
//
// 验证规则:
//   - TrimSpace 后为空视为直连
//   - url.Parse 失败返回 error（不含原始 URL，防凭据泄露）
//   - Host 为空返回 error（用 Redacted() 脱敏）
//   - Scheme 必须为 http/https/socks5/socks5h
//   - socks5:// 自动升级为 socks5h://（确保 DNS 由代理端解析，防止 DNS 泄漏）
func Parse(raw string) (trimmed string, parsed *url.URL, err error) {
	trimmed = strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, nil
	}

	trimmed = escapeUserinfo(trimmed)
	parsed, err = url.Parse(trimmed)
	if err != nil {
		// url.Error 包含原始 URL；不能将其拼入响应或日志，避免泄漏凭据。
		return "", nil, errors.New("invalid proxy URL")
	}

	if parsed.Host == "" || parsed.Hostname() == "" {
		return "", nil, fmt.Errorf("proxy URL missing host: %s", parsed.Redacted())
	}

	scheme := strings.ToLower(parsed.Scheme)
	if !allowedSchemes[scheme] {
		return "", nil, fmt.Errorf("unsupported proxy scheme %q (allowed: http, https, socks5, socks5h)", scheme)
	}

	// 自动升级 socks5 → socks5h，确保 DNS 由代理端解析，防止 DNS 泄漏。
	// Go 的 golang.org/x/net/proxy 对 socks5:// 默认在客户端本地解析 DNS，
	// 仅 socks5h:// 才将域名发送给代理端做远程 DNS 解析。
	if scheme == "socks5" {
		parsed.Scheme = "socks5h"
		trimmed = parsed.String()
	}

	return trimmed, parsed, nil
}

// escapeUserinfo 允许直接粘贴含 Unicode 或空格的代理凭据。
// 仅编码认证部分，保留已有百分号编码，避免改变密码或 URL 分隔符的含义。
func escapeUserinfo(raw string) string {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return raw
	}
	start := schemeEnd + 3
	end := len(raw)
	if i := strings.IndexAny(raw[start:], "/?#"); i >= 0 {
		end = start + i
	}
	at := strings.LastIndexByte(raw[start:end], '@')
	if at < 0 {
		return raw
	}
	end = start + at
	var encoded strings.Builder
	encoded.WriteString(raw[:start])
	const hex = "0123456789ABCDEF"
	for i := start; i < end; i++ {
		b := raw[i]
		if b >= 0x80 || b == ' ' {
			encoded.WriteByte('%')
			encoded.WriteByte(hex[b>>4])
			encoded.WriteByte(hex[b&15])
		} else {
			encoded.WriteByte(b)
		}
	}
	encoded.WriteString(raw[end:])
	return encoded.String()
}
