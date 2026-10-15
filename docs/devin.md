# Devin 原生接入

实现参考本地 `/Volumes/workspace/CLIProxyAPI`，对应上游
[CLIProxyAPI 提交 5fc580b1](https://github.com/router-for-me/CLIProxyAPI/tree/5fc580b1d72d87a7bcfe5cfb6f479c1aea5625b3)。
协议代码及模型目录的 MIT 许可保存在 `backend/internal/pkg/devin/LICENSE.CPA`，来源说明见同目录 `NOTICE`。
Devin 转发运行在 sub2api 进程内，无需启动 CPA 或新增服务。

## 添加账号

1. 在管理后台创建账号时选择 **Devin**，填写名称和所需代理。
2. 点击「生成 Devin 登录链接」，在 Devin 页面完成登录，将页面显示的授权码粘贴回来兑换。
3. 保存账号，并绑定 Devin 分组或组合分组。

也可直接输入 `devin-session-token$…`。凭据保存在 `credentials.session_token`，账号类型为 `oauth`；普通账号读取接口会脱敏。
编辑时留空保留原凭据；重新登录后保存即可替换。Devin 登录不使用 OpenAI/Anthropic 的 refresh token 接口。
登录链接有效期 10 分钟、一次性使用；登录期间切换代理须重新生成链接。待兑换会话保存在当前进程内，重启后须重建链接。
自定义上游地址只影响推理流量，登录和授权码兑换仍使用 Devin 官方域名。

## 请求与协议

- 支持 `/v1/responses`、`/v1/chat/completions`、`/v1/messages` 的文本、思考、函数工具调用与 base64 图片输入，包含流式和非流式输出。
- 出站沿用 CPA 的 Connect-RPC/protobuf，目标为 `server.codeium.com` 的 `ApiServerService/GetChatMessage`，使用 Devin session token。
- 复用 sub2api 现有鉴权、账号代理、调度、模型映射、用量计费和错误切换。
- 模型 UID 和思考强度按 CPA 映射；模型列表是上述提交的固定快照，不代表当前账号有权使用全部模型。
- 保留调用方系统指令和工具说明；不采用 CPA 的品牌文案过滤。
- 供应商思考签名在 Chat Completions 的 `reasoning_signature`、Responses 的 `encrypted_content`、Messages 的 `thinking.signature` 中回传。客户端需保留它们以完成多轮调用。
- 与 CPA 相同，思考之后的正文/工具会等待晚到的签名完整后再发送。截断流、缺少终止帧或用量、HTTP 200 内的 Connect 错误均不能当成成功。
- 会话标识按上游账号和调用方 API key 隔离；优先采用客户端会话 ID，没有时从首条用户消息派生。
- 缓存读、缓存写、输入、输出 token 分别进入原有用量体系。价格仍由 sub2api 的模型定价/渠道配置决定，接入 Devin 不会自动查询上游余额或价格。

暂不支持远程图片 URL、音视频、结构化 `response_format`、强制指定 `tool_choice`、`n > 1`、原生 Responses compaction、embedding、生图及独立搜索端点。
这些接口不能借用 Devin token 调用其他供应商服务。服务端内置工具不在当前实现范围，使用客户端函数工具。

## ChatGPT 额度

[Devin 官方说明](https://docs.devin.ai/admin/billing/chatgpt)要求在 Devin 中关联 ChatGPT 并开启使用 ChatGPT plan。
本接入沿用 CPA 的推理请求，不提供强制指定账单归属的开关。额度归属及用尽后的回退由 Devin 决定。

本地验证使用模拟的 Connect 帧，验证了三种入口、流式/非流式、工具/签名多轮、PKCE、用量及错误处理。原生帧最大 16 MiB，解压及累计响应最大 64 MiB；等待签名的输出队列最多 65,536 个分片。
**尚未用真实 Devin 账号验证登录、推理和 ChatGPT 扣量。** 上线验收需对比调用前后的 Devin/ChatGPT 用量；不能将本地测试通过视为额度链路已验证。
