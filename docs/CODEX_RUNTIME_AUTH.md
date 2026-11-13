# Codex Runtime Auth 与网关凭据边界

核验日期：2026-11-13。这里记录公开客户端源码的行为，不能据此推断 OpenAI 服务端的完整风控规则。

## 源码核验事实

核验对象：最新稳定版 [0.168.0](https://github.com/openai/codex/releases/tag/rust-v0.168.0)，
以及官方 main 提交 [`c899e21cda29fdd422898ffa54893f67ece34039`](https://github.com/openai/codex/tree/c899e21cda29fdd422898ffa54893f67ece34039)。

完成前再次核对 main，已推进至 [`69231e119bfca0b14453515e97d99688ce1c47c9`](https://github.com/openai/codex/tree/69231e119bfca0b14453515e97d99688ce1c47c9)。
下述校验、provider 选择、地址分类、功能默认值，以及 runtime 请求头和签名实现这六个文件的 SHA-256
与首次核验版本完全一致，结论保持不变。

| 行为 | 0.168.0 | 核验的 main |
| --- | --- | --- |
| 区分受支持的 OpenAI 地址、不支持的 OpenAI 地址、其他服务地址 | 存在 | 存在 |
| 校验账号／组织选择与注册 actor 一致 | 存在 | 存在 |
| 检查 provider 选中的凭据能否用于 Runtime Auth | 存在 | 存在，支持显式 API Key 的路径有扩展 |
| 检查请求和 runtime 注册的生产／staging 环境一致 | 此文件中尚无此检查 | 存在 |
| `runtime_agent_instances` 功能默认开启 | 否 | 否 |

对应源码：

- [main 的 Runtime Auth 校验](https://github.com/openai/codex/blob/c899e21cda29fdd422898ffa54893f67ece34039/codex-rs/model-provider/src/runtime_auth.rs)。
- [0.168.0 的 Runtime Auth 校验](https://github.com/openai/codex/blob/rust-v0.168.0/codex-rs/model-provider/src/runtime_auth.rs)。
- [地址分类](https://github.com/openai/codex/blob/c899e21cda29fdd422898ffa54893f67ece34039/codex-rs/http-client/src/openai_endpoints.rs)：
  自定义网关域名归为 `Other`；只有不受支持的 OpenAI 自有地址归为 `Unsupported`。
- [provider 的路径选择](https://github.com/openai/codex/blob/c899e21cda29fdd422898ffa54893f67ece34039/codex-rs/model-provider/src/provider.rs)：
  自定义 provider 地址为 `Other` 时，不选用该路径的 Runtime Auth。
- [功能默认值](https://github.com/openai/codex/blob/c899e21cda29fdd422898ffa54893f67ece34039/codex-rs/features/src/lib.rs)：
  `runtime_agent_instances` 为开发中功能，默认关闭。

`installation_id` 和 `x-openai-agent-assertion` 在 0.167.1 已存在：

- [0.167.1 的安装 ID](https://github.com/openai/codex/blob/rust-v0.167.1/codex-rs/core/src/installation_id.rs)。
- [0.167.1 的 Runtime Auth 请求头](https://github.com/openai/codex/blob/rust-v0.167.1/codex-rs/runtime-agent-instance/src/auth.rs)。

在上述 Runtime Auth 实现中，没有发现按 `Via`、`X-Forwarded-For`、TLS 指纹、出口 IP 数量
判断反代或共享人数并自动封禁账号的逻辑。这只限定于本次审查的公开客户端代码。
“这些信息是否被服务端用于其他判断”无法由客户端源码证实。

官方文档明确提供[自定义网关接入方式](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway)。
因此，“使用自定义网关就会被该校验识别并封禁”不是此次源码核验支持的结论。

## sub2api 的处理

sub2api 使用网关自身的 API Key 验证客户端，并由调度器选择上游凭据。
客户端凭据与选中的上游凭据可能属于不同账号，两者的身份材料不能混用。

- HTTP、HTTP 透传、WebSocket 请求头构建器均不透传客户端的
  `x-openai-agent-assertion`、`ChatGPT-Account-ID`、`OpenAI-Organization`、`OpenAI-Project`。
- 禁止通过账号 `header_overrides` 保存或注入 `x-openai-agent-assertion`。
  保存校验、前端校验、出站时读取旧配置的过滤均生效。
- API Key 账号仍可显式配置自己的 `OpenAI-Organization`、`OpenAI-Project`。
- ChatGPT 账号头仅从当前选中的 OAuth 凭据或影子账号的母账号生成。
  重新设置时先清除旧的账号 ID 和 FedRAMP 头，包括不同大小写的残留。
- 现有 Agent Identity 账号继续用自身保存的密钥逐次生成 `Authorization: AgentAssertion ...`。
  这是现有 Agent Identity 协议，不能等同于新 Runtime Auth 的 JWS 证明。

新 Runtime Auth 支持双头模式（Bearer 加 `x-openai-agent-assertion`）和仅断言模式。
其证明绑定已注册 runtime，不能靠伪造安装 ID、修改请求头或复用其他账号证明来满足校验。
本次修复不实现新的 runtime 注册协议，也不承诺规避服务端识别或风控。

## 回归验证

`openai_runtime_auth_boundary_test.go` 在三个出站构建器中同时注入客户端证明、客户端选择头，
以及历史配置中的静态证明，确认最终只使用选中的上游凭据，且合法 API Key 组织／项目配置保留。
另覆盖换号后缺少账号 ID 的情况，确认不会沿用上一账号的选择头。

验证命令：

```sh
# backend/
go test -tags=unit ./internal/service -run 'TestOpenAIRequestBuildersDoNotMixRuntimeProofWithSelectedCredential|TestSetOpenAIChatGPTAccountHeadersClearsPreviousAccount|TestNormalizeHeaderOverrideCredentials|TestApplyHeaderOverrides|TestResolveAndSetOpenAIChatGPTAccountHeaders|Test.*AgentIdentity|TestOpenAIGatewayService_BuildOpenAIWSHeaders' -count=1

# frontend/
./node_modules/.bin/vitest run src/components/account/__tests__/credentialsBuilder.spec.ts
```
