-- v0.2.7.7 部署迁移：KEYS[1] 由迁移前确认的 OpenAI 旧采票冷却账号 ID 构造。
-- 原子检查当前值，绝不覆盖期间新产生的其他限流或人工设置。
local value = redis.call('GET', KEYS[1])
if not value then return 0 end
local ok, state = pcall(cjson.decode, value)
if ok and type(state) == 'table' and state.error_message == 'codex ticket attempts exhausted' then
    return redis.call('DEL', KEYS[1])
end
return 0
