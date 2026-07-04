# USTC iWAN Tauri 客户端

面向 x86_64 Linux 的 Tauri 2 桌面客户端，用于完成 USTC iWAN OAuth 登录、获取 SDWAN 节点并启动本地 TUN 代理。

## 项目结构

- `src-tauri/`: Rust 后端，负责 PKCE、HTTP、HMAC、deep link 回调和 JSON 输出。
- `src/`、`index.html`: 前端界面，只触发登录、展示脱敏节点并控制代理连接。
- `src-tauri/tauri.conf.json`: 注册 `com.panabit.mobile://` URL scheme，浏览器 OAuth 回调会跳回本程序。
- `src-tauri/src/proxy.rs`: Linux TUN 代理 helper 逻辑，复用 CLI 的 iWAN UDP/TUN 协议实现。

输出文件写入 Tauri 应用数据目录：

- `iwan_credentials.json`
- `iwan_keepalive.json`

前端不会展示用户名、密码、连接命令或输出目录。不要用 `sudo` 启动 GUI；点击节点连接时，用户权限主程序会先检查 `iproute2`、`/dev/net/tun`、默认路由、`pkexec` 和图形授权环境，然后通过 `pkexec` 拉起 root 权限的 `--iwan-service`。GUI 通过 `/tmp/ustc-iwan/iwan-service.sock` 控制 root service，root service 再启动和管理 `--iwan-proxy` 代理进程。代理默认使用 `iwan0` TUN 网卡，但不会接管系统默认路由。每次启动代理时都会使用 `114.114.114.114` 查询 `api.LLM.USTC.EDU.CN` 和 `llm.USTC.EDU.CN` 的 IPv4 地址，同时合并系统实际解析出的 IPv4 地址，避免浏览器访问的 CNAME 目标未进入 TUN。只把解析出的 `/32` 路由到 TUN。停止代理或退出 GUI 时会恢复这些目标和 SDWAN 节点的原始精确路由。

Service/TUN 排查：

```bash
ls -l /tmp/ustc-iwan/iwan-service.sock
ip link show iwan0
ip addr show iwan0
ip route
ps -ef | grep -E 'ustc-iwan|iwan-service|iwan-proxy'
```

## 运行

需要 Node.js、npm、Rust 和 Cargo。

```bash
npm install
npm run dev
```

构建安装包：

```bash
npm run build
```

## GitHub Actions 构建 AppImage

仓库包含 `.github/workflows/appimage.yml`，上传到 GitHub 后可以自动在 `ubuntu-22.04` 上构建 x86_64 AppImage。

触发方式：

- 在 GitHub Actions 页面手动运行 `Build Linux AppImage`，构建结果会作为 artifact 上传。
- 推送 `v*` tag，例如 `v0.1.0`，会构建 AppImage 并附加到 GitHub Release。

```bash
git tag v0.1.0
git push origin v0.1.0
```

AppImage 输出路径：

```text
src-tauri/target/x86_64-unknown-linux-gnu/release/bundle/appimage/*.AppImage
```

## URL 回调测试

应用运行后，可以用系统 opener 测试 scheme 是否会唤起应用：

```bash
xdg-open 'com.panabit.mobile://oauth2redirect?code=test&state=test'
```

正常 OAuth 流程里 state 会由应用生成并校验，手工测试的 state 不匹配时会被拒绝。
