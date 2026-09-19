# 分支发布版本

从 `v0.2.7.1` 开始，发布号采用 `vX.Y.Z.N`：

- `X.Y.Z` 是已合入的上游版本。
- `N` 是分支修订号，从 1 开始递增；升级上游时重新从 1 开始。
- Git 标签、GitHub Release、镜像标签、二进制和界面展示同一四段版本。

例如 `v0.2.7.1` → `v0.2.7.2` → `v0.2.8.1`。发布时先修改
`backend/cmd/server/VERSION`，提交后打 annotated tag 并推送。

构建入口 `.github/workflows/release.yml` 调用 `scripts/release-version.sh`
检查 tag。GoReleaser 固定为 2.18.2，使用 `--skip=validate` 保留非 semver
的四段 tag；其 `.Version` 来自原始 tag。主/次版本镜像别名通过工作流显式传入，
不使用 GoReleaser 在跳过 semver 解析后留空的字段。

插件的宿主版本范围按前三段检查，但仍展示完整四段版本。插件仅声明测试过上游
`0.2.7` 时，分支 `0.2.7.1` 标记为「范围兼容、未经测试」，启用仍需管理员确认。
插件自身的版本和签名清单保持原样。

应用更新检查指向 `slovx2/sub2api`，比较全部四段，避免忽略修订号更新。

内置 292 打票实现已撤回；通过独立的 OpenAI OAuth Transport 插件提供。
安装、启用插件与配置其打票代理是不同操作，代理未配置时不自动开启打票。
