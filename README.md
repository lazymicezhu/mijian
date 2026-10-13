# 密笺 Mijian

一个简单的私人文字短链接分享网站。所有人共用一个访问密码；首次登录后，同一浏览器记住登录状态 30 天。输入文字后生成随机短链接，已登录的访问者打开链接即可查看原文。

前端使用原生 HTML、CSS 和 JavaScript。可部署到 **Cloudflare Pages + Functions + D1**，也可使用原有的 Node.js + SQLite 服务。文字加密后保存在数据库，链接只携带固定 16 个字符的随机编号，长度不会随文字增加。

## 部署到 Cloudflare

按[Cloudflare 部署指南](docs/cloudflare.md)连接 GitHub 仓库、创建 D1 数据库并配置共用密码和加密密钥即可，无需另外租服务器。

| Pages 构建设置 | 值 |
| --- | --- |
| 仓库 | `lazymicezhu/mijian` |
| 生产分支 | `main` |
| 框架预设 | `None` |
| 构建命令 | `exit 0` |
| 输出目录 | `public` |
| 根目录 | 保持默认 |

Functions 需要名为 `DB` 的 D1 绑定、`ACCESS_PASSWORD`、`ENCRYPTION_KEY` 和 `ADMIN_PASSWORD` 三项秘密配置，以及必填的 `PUBLIC_URL`。先创建不含秘密配置的 Pages 项目，获得稳定的 `https://项目名.pages.dev` 地址，再统一填写配置并重新部署。`PUBLIC_URL` 使用该稳定地址或已生效的自定义域名，不使用带部署编号的临时地址。

依次执行 `migrations/` 中的两个建表文件。本地预览中的数据不会自动上传到 D1；首次部署从空数据库开始。

## 本地运行 Node.js 版

需要 Node.js 22.13 或更新版本。Node.js 服务本身不需要第三方依赖。

```sh
npm run dev
```

默认地址为 `http://127.0.0.1:8877`。第一次运行会在终端显示随机生成的共用密码；请记下密码。开发服务只监听本机。

数据默认保存在项目的 `.data/` 中，也可以用环境变量 `DATA_DIR` 指定存储目录。SQLite 会保存加密文字和登录会话，正常重启不会丢失。开发模式的加密密钥与密码校验值保存在数据目录下的 `instance.json` 中。

本机链接只能在这台电脑上打开。接入真实域名和服务器之后，其他人才能通过互联网访问。

## 使用

1. 输入共用密码进入网站。
2. 输入文字，点击“生成链接并复制”；生成成功后自动复制带前缀的分享文字，浏览器不允许自动复制时可点击“复制链接”。
3. 将分享文字发送给知道共用密码的人，格式为 `密文请点击链接查看：https://你的域名/m/16字符随机编号`。
4. 对方首次访问时输入密码；登录后直接显示链接对应的文字。

点击“退出”会撤销当前浏览器的登录状态。更换设备、清除 Cookie 或登录过期后需要重新输入密码。知道共用密码且拿到链接的人都可以查看对应内容；网站没有个人账号和每条内容的单独权限。

## 本地运行 Cloudflare 版

需要 Node.js 22.13 或更新版本，在项目根目录运行：

```sh
npm ci
cp .dev.vars.example .dev.vars
```

在 `.dev.vars` 中填写开发用的 `ACCESS_PASSWORD`、`ENCRYPTION_KEY` 和独立的 `ADMIN_PASSWORD`，保留 `LOCAL_DEV=true`，然后运行：

```sh
npm run db:local
npm run dev:cf
```

默认打开 `http://localhost:8878`。初始化命令读取 `wrangler.local.jsonc`，预览命令使用相同的本地数据库编号；数据保存在 `.wrangler/`，不会连接正式数据库。`.dev.vars` 和本地数据已被 `.gitignore` 排除。

## 管理后台（Cloudflare 版）

打开 `https://你的域名/admin`，使用独立的 `ADMIN_PASSWORD` 登录。管理员密码须与共用访问密码不同，至少 12 个 UTF-8 字节。管理登录状态保留 8 小时。

- 查看创建记录：消息编号、创建时间、创建者访客编号、IP、文字字节数及查看次数。
- 点击“查看原文”读取内容，或筛选某条文字的解密记录。
- 查看成功解密的时间、访客编号及 IP。管理员查看原文也会记为管理员操作。
- 时间显示为 UTC+8，精确到秒；列表分页显示。

访客编号用于区分浏览器，Cookie 保存 180 天；清除 Cookie 或使用无痕窗口会产生新编号，多个使用者也可能共用同一 IP。它不能证明某个真实人物读过内容。解密记录表示服务器成功返回文字，不代表用户实际阅读。前台不要求额外填写身份信息，并会提示记录访问信息。

普通访问密码不能进入后台。后台和审计功能仅在 Cloudflare 版提供；原 Node.js 预览继续保留原有分享功能。

## 数据与密码

- 每条文字使用 AES-256-GCM 加密后保存，采用独立随机 nonce，并认证消息编号。
- Cloudflare 版的访问密码保存在平台秘密配置中，通过 Web Crypto 校验；Node.js 版使用 scrypt。数据库只保存会话令牌的哈希，不保存访问密码明文。
- 浏览器只保存登录 Cookie，不把访问密码或正文写入 localStorage。
- 这是由服务器控制访问和解密的网站，服务器持有密钥，能够读取原文，不属于端到端加密。
- 单条文字上限为 100000 个 UTF-8 字节，约 3 万个常见汉字。链接的随机编号固定为 16 个字符。
- 普通用户没有内容列表；管理员可以在后台查看。当前没有删除按钮或到期自动删除，文字和访问记录会持续保留。
- Cloudflare 版须备份 D1 数据并保管 `ENCRYPTION_KEY`；Node.js 开发模式须备份数据库及 `instance.json`，正式环境须备份数据库并保管 `ENCRYPTION_KEY`。丢失密钥后无法恢复原文。备份正在写入的 SQLite 数据库时应使用 SQLite 备份工具，或停止服务后复制完整数据目录。

## 在自己的服务器运行 Node.js 版

正式启动使用 `npm start`，通过部署平台或进程环境提供以下变量：

| 变量 | 用途 |
| --- | --- |
| `PUBLIC_URL` | 网站 HTTPS 地址，例如 `https://notes.example.com`，不带路径 |
| `ACCESS_PASSWORD` | 共用访问密码，8 至 1024 个 UTF-8 字节，建议使用较长的随机密码 |
| `ENCRYPTION_KEY` | 32 字节随机密钥的标准 Base64；须稳定保存，不能随重启重新生成 |
| `DATA_DIR` | 持久化数据目录，位于公开网站文件之外 |
| `PORT` | 后端端口，默认 3000 |
| `HOST` | 后端监听地址，默认 `127.0.0.1`；容器中需要时显式设为 `0.0.0.0` |
| `TRUST_PROXY` | 同机 HTTPS 反向代理时设为 `loopback`，否则不设置 |

正式环境通过 HTTPS 反向代理连接后端，代理必须保留 `Host` 并覆盖（不能透传用户自带的）`X-Real-IP`。启用 `TRUST_PROXY=loopback` 时，后端只信任来自本机代理的客户端 IP。不要公开后端 HTTP 端口。不同部署平台的代理配置需按实际网络拓扑调整。

正式 Cookie 使用 Secure、HttpOnly 和 SameSite=Lax。修改访问密码后重启会撤销已有登录会话，但不影响已保存文字。更换加密密钥需要迁移已有数据；密钥不匹配时程序会拒绝启动。

程序不会自动读取 `.env`。可复制 `.env.example` 为 `.env` 后填写，使用 `node --env-file=.env server.mjs` 加载，或直接由运行环境注入变量。

生成一次正式环境所需的随机加密密钥：

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

将输出保存为 `ENCRYPTION_KEY`，不要每次启动时重新生成。共用密码、密钥、数据目录和本地配置文件不应提交到 Git 仓库。

## 项目结构

```text
public/                 网页、样式和浏览器脚本
functions/              Cloudflare Pages Functions
migrations/             D1 建表 SQL
docs/cloudflare.md      Cloudflare 部署步骤
server.mjs              Node.js 服务与 SQLite 存储
tests/                  后端集成测试
package.json            启动和测试命令
```

## 验证

```sh
npm ci
npm test
npm run build:cf
```

也可用 `npm run test:node` 或 `npm run test:cf` 单独运行某一版本的测试。

Node.js 测试使用独立临时数据库，覆盖访问控制、中文与表情文字往返、错误密码、来源检查、加密存储与篡改检测、重启持久化、会话撤销、输入长度限制及生产 Cookie 和代理配置。Cloudflare 测试使用本地 Workers 运行环境与 D1 模拟数据库，不访问线上数据。
