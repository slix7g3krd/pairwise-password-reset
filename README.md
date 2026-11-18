# pairwise-password-reset

密码重置邮件一接入，账号接管链就通了：token 用 md5(邮箱+时间戳) 生成，时间戳可枚举；同一个 token 能重复使用；有效期设了 7 天；邮箱不存在和发送成功返回不同文案，能枚举用户；token 没绑定当前密码哈希，改密后旧链接还能用；重置链接用 Host 头拼域名，攻击者改 Host 就能拿到 token；用户连续点“忘记密码”会生成多个同时有效的 token；token 只有 8 位十六进制；token 明文写进访问日志；接口没有频率限制；邮箱大小写不归一；重置接口不校验 CSRF；改密后旧会话不失效。security/password_reset.py 是核心，tests/test_password_reset.py 15个红。要修的是：高熵 token；一次性消费；短有效期；统一响应；绑定密码哈希；固定域名；旧 token 失效；长度与字符集；日志脱敏；限流；邮箱归一；CSRF；会话吊销。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：其他；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
