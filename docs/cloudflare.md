# 部署密笺到 Cloudflare

密笺使用 Pages 显示网页、Pages Functions 处理登录与加解密、D1 保存加密文字。以下步骤通过 Cloudflare 控制台完成，代码从 GitHub 自动部署。

## 1. 创建 D1 数据库

登录 [Cloudflare 控制台](https://dash.cloudflare.com/)，进入 **存储和数据库 → D1 SQL 数据库（D1 SQL Database）→ 创建数据库**，命名为 `mijian-db`。

进入数据库的 **Console（控制台）**，依次复制并执行以下两个文件的完整内容，建立文字、会话和后台访问记录表：[D1 官方操作说明](https://developers.cloudflare.com/d1/get-started/)

1. [`migrations/0001_initial.sql`](../migrations/0001_initial.sql)
2. [`migrations/0002_admin_audit.sql`](../migrations/0002_admin_audit.sql)

首次部署使用空数据库，本机预览中的文字和链接不会自动上传。

## 2. 连接 GitHub 创建 Pages 项目

进入 **Workers & Pages → 创建应用 → Pages → 导入现有 Git 仓库**，授权连接 GitHub 并选择 `lazymicezhu/mijian`，填写：

| 设置 | 值 |
| --- | --- |
| 项目名称 | `mijian`，如已占用可另取名称 |
| 生产分支 | `main` |
| 框架预设 | `None` |
| 构建命令 | `exit 0` |
| 构建输出目录 | `public` |
| 根目录 | 保持默认 |

首次先不填写访问密码和加密密钥，点击保存并部署。项目创建后，记下稳定的 `https://项目名.pages.dev` 地址。此时网站尚不能登录，完成下一步配置后才能使用。[Pages 构建设置说明](https://developers.cloudflare.com/pages/framework-guides/deploy-anything/)

## 3. 绑定数据库并填写秘密配置

在 Pages 项目的 **设置 → 绑定（Bindings）→ 添加 → D1 数据库** 中，将变量名设为 **`DB`**，选择 `mijian-db`。变量名区分大小写。[绑定说明](https://developers.cloudflare.com/pages/functions/bindings/#d1-databases)

在 **设置 → 变量和秘密（Variables and Secrets）** 选择 **Production（生产）** 环境，添加：

| 名称 | 内容 | 类型 |
| --- | --- | --- |
| `ACCESS_PASSWORD` | 所有人共用的访问密码，支持中文；8 至 1024 个 UTF-8 字节 | Secret／加密 |
| `ADMIN_PASSWORD` | 独立的管理员密码，至少 12 个 UTF-8 字节，不能与共用密码相同；只供你进入后台使用 | Secret／加密 |
| `ENCRYPTION_KEY` | 下方命令生成的 32 字节随机密钥，标准 Base64 格式 | Secret／加密 |
| `PUBLIC_URL` | 必填，使用上一步的稳定地址 `https://项目名.pages.dev`，或已生效的自定义域名，例如 `https://notes.example.com`；不带路径 | 普通变量 |

秘密配置须选择 **Encrypt（加密）**，不要写进 GitHub 文件。[秘密配置说明](https://developers.cloudflare.com/pages/functions/bindings/#secrets)

在本机终端运行一次以下命令生成密钥：

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
```

将输出完整保存到 `ENCRYPTION_KEY`，并自行留存。以后部署继续使用同一个值；更换或丢失它会导致旧文字无法解密。不要在 Cloudflare 正式环境设置 `LOCAL_DEV=true`。

`PUBLIC_URL` 不能省略，也不要填 `https://部署编号.项目名.pages.dev` 这样的单次部署地址。请统一从填写的稳定地址访问网站；其他域名的接口会被拒绝，避免历史部署继续使用旧密码访问数据库。本地 `LOCAL_DEV=true` 预览可不填此变量。

确认 `DB`、三项秘密配置和 `PUBLIC_URL` 均已填写，再回到 **部署（Deployments）**，对最新生产部署选择 **重试部署（Retry deployment）**。这些配置需要新部署才能生效。预览环境如需启用，请使用独立数据库、密码、密钥和固定的预览分支地址，不要绑定生产数据。

## 4. 检查网站并绑定域名

打开 `PUBLIC_URL` 中填写的地址，输入共用密码，生成一条测试文字并打开分享链接。再用无痕窗口打开同一链接，确认先要求输入密码、登录后能看到文字。

随后访问 `https://你的域名/admin`，使用 `ADMIN_PASSWORD` 登录。后台显示创建记录和成功解密记录，包括时间、访客编号和 IP；可按某条消息筛选记录、查看原文。时间按 UTC+8 显示。访客编号区分浏览器，无法确认真实姓名；无痕窗口或清除 Cookie 会产生新编号。管理员查看原文也会留下记录。

在 Pages 项目的 **自定义域（Custom domains）→ 设置域名（Set up a domain）** 中输入你的域名，按提示配置 DNS。根域名需要接入同一 Cloudflare 账号的 DNS；子域名可按提示添加指向 Pages 地址的 CNAME。先在 Pages 中添加域名，再修改 DNS。[自定义域名说明](https://developers.cloudflare.com/pages/configuration/custom-domains/)

域名生效后，把 `PUBLIC_URL` 改为该 HTTPS 地址并重新部署，之后统一从新域名访问。不同域名的 Cookie 不互通，切换后需要重新登录。之前分享的 Pages 地址需要换成新域名，`/m/` 后的编号保持不变。

## 后续更新

推送到 `main` 后，Pages 会自动部署新版本。通常不需要重新建库或更换密钥。修改 `ACCESS_PASSWORD` 并重新部署后，现有浏览器需要用新密码登录，已保存文字不受影响。

如果页面能显示但无法登录，检查 `DB` 绑定、两个建表文件、三项秘密配置以及是否已重新部署。`PUBLIC_URL` 应与浏览器当前域名一致。更多排查信息可在 Pages 部署的 Functions 日志中查看。

## 可选：用命令初始化远程数据库

也可以在本机项目目录执行，替代第 1 步的控制台粘贴 SQL：

```sh
npm ci
npx wrangler login
npx wrangler d1 execute mijian-db --remote --file=migrations/0001_initial.sql
npx wrangler d1 execute mijian-db --remote --file=migrations/0002_admin_audit.sql
```

数据库需先在控制台创建。`--remote` 表示操作 Cloudflare 上的数据库；本地试运行请使用 `npm run db:local`。[D1 命令说明](https://developers.cloudflare.com/d1/wrangler-commands/#d1-execute)

仓库的 `wrangler.jsonc.example` 是可选配置模板。按上述控制台步骤部署时，无需复制成有效的 Wrangler 配置；这样绑定和变量统一由控制台管理。`wrangler.local.jsonc` 仅供本地命令显式加载，其中的数据库编号不会用于线上部署。
