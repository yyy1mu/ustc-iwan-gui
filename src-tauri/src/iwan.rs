use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(target_os = "linux")]
use std::{
    env,
    process::{Command, Stdio},
    thread,
};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager, State};
use url::Url;
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::proxy::ProxyConfig;
use crate::service::{
    ServiceRequest, ServiceResponse, ServiceStatus, SERVICE_PROTOCOL_VERSION, SERVICE_SOCKET,
};

type HmacSha256 = Hmac<Sha256>;

const AUTH_URL: &str = "https://auth.ivpn.ustc.edu.cn/login/oauth/authorize";
const TOKEN_URL: &str = "https://auth.ivpn.ustc.edu.cn/api/login/oauth/access_token";
const CLIENT_ID: &str = "afc6479ffb531d71daef";
const REDIRECT: &str = "com.panabit.mobile://oauth2redirect";
const REDIRECT_SCHEME: &str = "com.panabit.mobile";
const REDIRECT_HOST: &str = "oauth2redirect";
const SCOPE: &str = "openid profile email offline_access";
#[cfg(target_os = "linux")]
const LLM_ROUTE_HOSTS: &[&str] = &["api.LLM.USTC.EDU.CN", "llm.USTC.EDU.CN"];

const KC_IDP: &str = "USTC\u{200c}_OAUTH";
const ORG: &str = "USTC\u{200c}";

const CONTROLLER: &str = "https://crtl.ivpn.ustc.edu.cn";
const DOMAIN: &str = "iwan.ustc";
const FIXED_KEY: &str = "fixed-app-key";
const CONTROLLER_APP_ID: &str = "controller-ustc";
const CONTROLLER_APP_SECRET: &str = "ca6a3532abd2986a03b86b3a";

#[derive(Default)]
pub struct FlowState {
    pending: Mutex<Option<PendingLogin>>,
    credentials: Mutex<Option<CredentialData>>,
}

#[derive(Clone)]
struct PendingLogin {
    verifier: String,
    oauth_state: String,
    device_uuid: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStart {
    device_uuid: String,
    login_url: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusPayload {
    stage: String,
    message: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ErrorPayload {
    message: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FlowResult {
    domain: String,
    device_uuid: String,
    app_id: String,
    access_token_preview: String,
    servers: Vec<ServerView>,
    dns: DnsConfig,
    controller_messages: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    id: usize,
    name: String,
    host: String,
    port: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerCredential {
    name: String,
    host: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsConfig {
    servers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CredentialsFile {
    domain: String,
    servers: Vec<ServerCredential>,
    dns: DnsConfig,
}

#[derive(Debug, Serialize)]
struct KeepaliveFile {
    app_id: String,
    app_secret: String,
    device_uuid: String,
    access_token: String,
}

#[derive(Debug, Clone)]
struct CredentialData {
    domain: String,
    device_uuid: String,
    app_id: String,
    access_token_preview: String,
    servers: Vec<ServerCredential>,
    dns: DnsConfig,
    controller_messages: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    running: bool,
    server_id: Option<usize>,
    server_name: Option<String>,
    tun_name: String,
    last_message: Option<String>,
    last_error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RequirementItem {
    name: String,
    ok: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

struct ControllerResult {
    messages: Vec<String>,
    servers: Vec<ServerCredential>,
}

#[tauri::command]
pub async fn start_login(
    app: AppHandle,
    state: State<'_, FlowState>,
) -> std::result::Result<LoginStart, String> {
    let device_uuid = Uuid::new_v4().to_string();
    let verifier = random_urlsafe(64);
    let challenge = pkce_challenge(&verifier);
    let oauth_state = random_urlsafe(18);
    let nonce = random_urlsafe(18);

    let params = [
        ("client_id", CLIENT_ID),
        ("redirect_uri", REDIRECT),
        ("response_type", "code"),
        ("scope", SCOPE),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("state", oauth_state.as_str()),
        ("nonce", nonce.as_str()),
        ("prompt", "login"),
        ("kc_idp_hint", KC_IDP),
        ("provider_hint", KC_IDP),
        ("provider", KC_IDP),
        ("organization", ORG),
        ("application", "Mobile_USTC"),
        ("method", "signup"),
    ];
    let login_url = format!(
        "{}?{}",
        AUTH_URL,
        serde_urlencoded::to_string(params).map_err(|err| err.to_string())?
    );

    {
        let mut pending = state
            .pending
            .lock()
            .map_err(|_| "登录状态锁定失败".to_string())?;
        *pending = Some(PendingLogin {
            verifier,
            oauth_state,
            device_uuid: device_uuid.clone(),
        });
    }

    emit_status(
        &app,
        "准备登录",
        &format!("device_uuid 已生成，redirect_uri={REDIRECT}"),
    );
    open::that_detached(&login_url).map_err(|err| format!("无法打开浏览器: {err}"))?;
    emit_status(
        &app,
        "等待回调",
        "请在浏览器完成 USTC 统一认证，系统会通过 URL scheme 回到本程序。",
    );

    Ok(LoginStart {
        device_uuid,
        login_url,
    })
}

#[tauri::command]
pub fn get_last_result(
    state: State<'_, FlowState>,
) -> std::result::Result<Option<FlowResult>, String> {
    state
        .credentials
        .lock()
        .map(|guard| guard.as_ref().map(to_flow_result))
        .map_err(|_| "结果状态锁定失败".to_string())
}

#[tauri::command]
pub fn get_proxy_status(state: State<'_, FlowState>) -> std::result::Result<ProxyStatus, String> {
    refresh_proxy_status(&state)
}

#[tauri::command]
pub fn check_requirements() -> Vec<RequirementItem> {
    proxy_requirements()
}

#[tauri::command]
pub fn start_proxy(
    app: AppHandle,
    state: State<'_, FlowState>,
    server_id: usize,
) -> std::result::Result<ProxyStatus, String> {
    start_proxy_inner(app, &state, server_id).map_err(|err| err.to_string())
}

#[tauri::command]
pub fn stop_proxy(
    app: AppHandle,
    state: State<'_, FlowState>,
) -> std::result::Result<ProxyStatus, String> {
    stop_proxy_inner(&app, &state).map_err(|err| err.to_string())
}

pub fn stop_proxy_on_exit() {
    let _ = service_request(crate::service::ServiceRequest {
        command: "stop".to_string(),
        config: None,
        server_id: None,
        server_name: None,
    });
}

pub fn handle_deep_link_urls(app: AppHandle, urls: Vec<String>) {
    for raw_url in urls {
        match parse_oauth_callback(&raw_url) {
            Ok(Some(callback)) => {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(err) = finish_login(app_handle.clone(), callback).await {
                        emit_error(&app_handle, &err.to_string());
                    }
                });
            }
            Ok(None) => {}
            Err(err) => emit_error(&app, &format!("无法解析回调 URL: {err}")),
        }
    }
}

async fn finish_login(app: AppHandle, callback: OAuthCallback) -> Result<()> {
    emit_status(
        &app,
        "收到回调",
        "浏览器已跳转回应用，正在校验 state 并交换 access_token。",
    );

    let pending = {
        let state = app.state::<FlowState>();
        let mut guard = state
            .pending
            .lock()
            .map_err(|_| anyhow!("登录状态锁定失败"))?;
        let pending = guard
            .as_ref()
            .ok_or_else(|| anyhow!("没有等待中的登录流程，请重新点击登录"))?;
        if pending.oauth_state != callback.state {
            return Err(anyhow!("OAuth state 不匹配，已拒绝该回调"));
        }
        guard.take().expect("pending login checked")
    };

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .context("创建 HTTP client 失败")?;

    let token = exchange_code(&client, &callback.code, &pending.verifier)
        .await
        .context("access_token 交换失败")?;
    emit_status(&app, "Token", "access_token 已获取，正在调用 controller。");

    let controller = run_controller_calls(&client, &token, &pending.device_uuid).await;
    emit_status(
        &app,
        "写入文件",
        "正在生成 iwan_credentials.json 和 iwan_keepalive.json。",
    );

    let credentials = write_outputs(&app, token, pending.device_uuid, controller)?;
    let result = to_flow_result(&credentials);
    {
        let state = app.state::<FlowState>();
        let mut guard = state
            .credentials
            .lock()
            .map_err(|_| anyhow!("结果状态锁定失败"))?;
        *guard = Some(credentials);
    }

    app.emit("iwan-result", result)?;
    Ok(())
}

async fn exchange_code(client: &reqwest::Client, code: &str, verifier: &str) -> Result<String> {
    let body = serde_urlencoded::to_string([
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", REDIRECT),
        ("client_id", CLIENT_ID),
        ("code_verifier", verifier),
    ])?;

    let response = client
        .post(TOKEN_URL)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await?;

    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "token endpoint HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        ));
    }

    let tokens: TokenResponse = serde_json::from_slice(&bytes)?;
    Ok(tokens.access_token)
}

async fn run_controller_calls(
    client: &reqwest::Client,
    token: &str,
    device_uuid: &str,
) -> ControllerResult {
    let mut messages = Vec::new();
    let mut servers = Vec::new();

    let auth_body = json!({
        "domain": DOMAIN,
        "device_id": device_uuid,
        "type": "android",
        "version": "1.0"
    });
    match controller_post(client, "/m/auth", auth_body, token).await {
        Ok(value) => {
            collect_server_credentials(&value, &mut servers);
            messages.push(format!("/m/auth OK: {}", compact_json(&value)));
        }
        Err(err) => messages.push(format!("/m/auth warning: {err}")),
    }

    let keepalive_body = json!({
        "domain": DOMAIN,
        "device_id": device_uuid,
        "type": "keepalive",
        "version": "0"
    });
    match controller_post(client, "/m/keepalive", keepalive_body, token).await {
        Ok(value) => {
            collect_server_credentials(&value, &mut servers);
            messages.push(format!("/m/keepalive OK: {}", compact_json(&value)));
        }
        Err(err) => messages.push(format!("/m/keepalive warning: {err}")),
    }

    dedupe_servers(&mut servers);
    ControllerResult { messages, servers }
}

async fn controller_post(
    client: &reqwest::Client,
    path: &str,
    body: Value,
    token: &str,
) -> Result<Value> {
    let body_bytes = serde_json::to_vec(&body)?;
    let mut request = client
        .post(format!("{CONTROLLER}{path}"))
        .bearer_auth(token)
        .header(CONTENT_TYPE, "application/json");

    for (key, value) in hmac_headers(
        "POST",
        path,
        "",
        &body_bytes,
        CONTROLLER_APP_ID,
        CONTROLLER_APP_SECRET,
    )? {
        request = request.header(key, value);
    }

    let response = request.body(body_bytes).send().await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "{path} HTTP {}: {}",
            status.as_u16(),
            String::from_utf8_lossy(&bytes)
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn hmac_headers(
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
    app_id: &str,
    app_secret: &str,
) -> Result<Vec<(&'static str, String)>> {
    let timestamp = unix_timestamp().to_string();
    let nonce = random_hex(16);
    let body_hash = sha256_hex(body);
    let canonical_query = canonical_query(query);
    let sign_string = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        path,
        canonical_query,
        body_hash,
        timestamp,
        nonce
    );

    let mut mac =
        HmacSha256::new_from_slice(app_secret.as_bytes()).map_err(|err| anyhow!("{err}"))?;
    mac.update(sign_string.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    Ok(vec![
        ("X-Auth-AppId", app_id.to_string()),
        ("X-Auth-Timestamp", timestamp),
        ("X-Auth-Nonce", nonce),
        ("X-Auth-Sign", signature),
    ])
}

fn write_outputs(
    app: &AppHandle,
    token: String,
    device_uuid: String,
    controller: ControllerResult,
) -> Result<CredentialData> {
    let dir = output_dir(app)?;
    fs::create_dir_all(&dir).with_context(|| format!("创建应用数据目录失败: {}", dir.display()))?;

    let servers = controller.servers;
    let dns = DnsConfig {
        servers: vec!["202.38.64.56".to_string(), "202.38.64.18".to_string()],
    };

    let credentials = CredentialsFile {
        domain: DOMAIN.to_string(),
        servers: servers.clone(),
        dns: dns.clone(),
    };
    let keepalive = KeepaliveFile {
        app_id: CONTROLLER_APP_ID.to_string(),
        app_secret: CONTROLLER_APP_SECRET.to_string(),
        device_uuid: device_uuid.clone(),
        access_token: token.clone(),
    };

    let credentials_path = dir.join("iwan_credentials.json");
    let keepalive_path = dir.join("iwan_keepalive.json");
    fs::write(&credentials_path, serde_json::to_vec_pretty(&credentials)?)?;
    fs::write(&keepalive_path, serde_json::to_vec_pretty(&keepalive)?)?;

    Ok(CredentialData {
        domain: DOMAIN.to_string(),
        device_uuid,
        app_id: CONTROLLER_APP_ID.to_string(),
        access_token_preview: preview_token(&token),
        servers,
        dns,
        controller_messages: controller.messages,
    })
}

fn collect_server_credentials(value: &Value, servers: &mut Vec<ServerCredential>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_server_credentials(item, servers);
            }
        }
        Value::Object(object) => {
            if let Some(server) = server_from_object(object) {
                servers.push(server);
            }
            for child in object.values() {
                collect_server_credentials(child, servers);
            }
        }
        _ => {}
    }
}

fn server_from_object(object: &Map<String, Value>) -> Option<ServerCredential> {
    let host = first_string(
        object,
        &[
            "host",
            "ip",
            "server",
            "addr",
            "address",
            "server_ip",
            "serverIp",
            "ipaddr",
            "ipAddr",
            "wan_ip",
            "wanIp",
        ],
    )?;
    let port = first_u16(
        object,
        &["port", "udp_port", "udpPort", "server_port", "serverPort"],
    )?;
    let name = first_string(
        object,
        &["name", "title", "line", "node", "isp", "remark", "label"],
    )
    .unwrap_or_else(|| host.clone());

    Some(ServerCredential {
        name,
        host,
        port,
        username: first_string(
            object,
            &[
                "username",
                "user",
                "account",
                "vpn_user",
                "vpnUser",
                "sdwan_user",
                "sdwanUser",
            ],
        ),
        password: first_string(
            object,
            &[
                "password",
                "pass",
                "passwd",
                "vpn_pass",
                "vpnPass",
                "sdwan_pass",
                "sdwanPass",
            ],
        ),
    })
}

fn first_string(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(value_as_string)
}

fn first_u16(object: &Map<String, Value>, keys: &[&str]) -> Option<u16> {
    keys.iter()
        .filter_map(|key| object.get(*key))
        .find_map(value_as_u16)
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        }
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_as_u16(value: &Value) -> Option<u16> {
    match value {
        Value::Number(value) => value.as_u64().and_then(|value| u16::try_from(value).ok()),
        Value::String(value) => value.trim().parse::<u16>().ok(),
        _ => None,
    }
}

fn dedupe_servers(servers: &mut Vec<ServerCredential>) {
    let mut deduped = Vec::new();
    for server in servers.drain(..) {
        if !deduped
            .iter()
            .any(|item: &ServerCredential| item.host == server.host && item.port == server.port)
        {
            deduped.push(server);
        }
    }
    *servers = deduped;
}

fn to_flow_result(data: &CredentialData) -> FlowResult {
    FlowResult {
        domain: data.domain.clone(),
        device_uuid: data.device_uuid.clone(),
        app_id: data.app_id.clone(),
        access_token_preview: data.access_token_preview.clone(),
        servers: data
            .servers
            .iter()
            .enumerate()
            .map(|(id, server)| ServerView {
                id,
                name: server.name.clone(),
                host: server.host.clone(),
                port: server.port,
            })
            .collect(),
        dns: data.dns.clone(),
        controller_messages: data.controller_messages.clone(),
    }
}

#[cfg(target_os = "linux")]
fn ensure_proxy_requirements() -> Result<()> {
    let failed = proxy_requirements()
        .into_iter()
        .filter(|item| !item.ok)
        .map(|item| format!("{}: {}", item.name, item.message))
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("代理运行环境不完整：{}", failed.join("；")))
    }
}

fn proxy_requirements() -> Vec<RequirementItem> {
    #[cfg(not(target_os = "linux"))]
    {
        vec![RequirementItem {
            name: "Linux".to_string(),
            ok: false,
            message: "TUN 代理只支持 Linux".to_string(),
        }]
    }

    #[cfg(target_os = "linux")]
    {
        let is_root = is_effective_root();
        let ip_path = find_program(
            "ip",
            &["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"],
        );
        let pkexec_path = find_program("pkexec", &["/usr/bin/pkexec", "/bin/pkexec"]);
        let has_display =
            env::var_os("WAYLAND_DISPLAY").is_some() || env::var_os("DISPLAY").is_some();
        let default_route_ok = ip_path
            .as_ref()
            .and_then(|path| {
                Command::new(path)
                    .args(["-4", "route", "show", "default"])
                    .output()
                    .ok()
            })
            .map(|output| output.status.success() && !output.stdout.is_empty())
            .unwrap_or(false);

        vec![
            RequirementItem {
                name: "Linux".to_string(),
                ok: true,
                message: "当前系统支持 TUN 代理".to_string(),
            },
            RequirementItem {
                name: "运行方式".to_string(),
                ok: !is_root,
                message: if is_root {
                    "请不要用 sudo 启动 GUI；root 权限只用于 iWAN service。".to_string()
                } else {
                    "GUI 正在以普通用户权限运行".to_string()
                },
            },
            RequirementItem {
                name: "/dev/net/tun".to_string(),
                ok: PathBuf::from("/dev/net/tun").exists(),
                message: if PathBuf::from("/dev/net/tun").exists() {
                    "TUN 设备可用".to_string()
                } else {
                    "缺少 TUN 设备，请加载 tun 模块".to_string()
                },
            },
            RequirementItem {
                name: "iproute2".to_string(),
                ok: ip_path.is_some(),
                message: ip_path
                    .as_ref()
                    .map(|path| format!("找到 {}", path.display()))
                    .unwrap_or_else(|| "缺少 ip 命令，无法配置网卡和路由".to_string()),
            },
            RequirementItem {
                name: "默认路由".to_string(),
                ok: default_route_ok,
                message: if default_route_ok {
                    "已检测到默认 IPv4 路由".to_string()
                } else {
                    "未检测到默认 IPv4 路由，无法安全切换代理路由".to_string()
                },
            },
            RequirementItem {
                name: "root 授权".to_string(),
                ok: pkexec_path.is_some(),
                message: pkexec_path
                    .as_ref()
                    .map(|path| format!("找到 {}", path.display()))
                    .unwrap_or_else(|| "缺少 pkexec，无法弹出 root service 授权".to_string()),
            },
            RequirementItem {
                name: "图形授权环境".to_string(),
                ok: has_display,
                message: if has_display {
                    "可弹出 polkit 授权窗口".to_string()
                } else {
                    "未检测到 DISPLAY/WAYLAND_DISPLAY，pkexec 可能无法弹出授权窗口".to_string()
                },
            },
        ]
    }
}

fn start_proxy_inner(app: AppHandle, state: &FlowState, server_id: usize) -> Result<ProxyStatus> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        let _ = state;
        let _ = server_id;
        return Err(anyhow!("Linux TUN 代理只支持 Linux"));
    }

    #[cfg(target_os = "linux")]
    {
        ensure_proxy_requirements()?;
        let credentials = state
            .credentials
            .lock()
            .map_err(|_| anyhow!("凭据状态锁定失败"))?
            .clone()
            .ok_or_else(|| anyhow!("请先登录获取 SDWAN 节点"))?;
        let server = credentials
            .servers
            .get(server_id)
            .cloned()
            .ok_or_else(|| anyhow!("无效的 SDWAN 节点"))?;

        let config = ProxyConfig {
            server: server.host.clone(),
            port: server.port,
            username: server
                .username
                .clone()
                .ok_or_else(|| anyhow!("当前 SDWAN 节点没有用户名，请先配置运行时凭据"))?,
            password: server
                .password
                .clone()
                .ok_or_else(|| anyhow!("当前 SDWAN 节点没有密码，请先配置运行时凭据"))?,
            encrypt: 1,
            mtu: 1400,
            tun_name: "iwan0".to_string(),
            route_hosts: LLM_ROUTE_HOSTS
                .iter()
                .map(|host| (*host).to_string())
                .collect(),
            route_cidr: None,
        };

        emit_status(&app, "授权", "正在确认 root service。");
        ensure_service_running(&app)?;
        let response = service_request(crate::service::ServiceRequest {
            command: "start".to_string(),
            config: Some(config),
            server_id: Some(server_id),
            server_name: Some(server.name),
        })?;
        if response.protocol_version != SERVICE_PROTOCOL_VERSION {
            return Err(anyhow!("root service 版本不匹配，请重新启动代理"));
        }
        if !response.ok {
            return Err(anyhow!(response.message));
        }
        let status = proxy_status_from_service(response.status);
        emit_proxy_status(&app, &status);
        emit_status(&app, "代理", "已向 root service 发送启动请求。");
        Ok(status)
    }
}

fn stop_proxy_inner(app: &AppHandle, state: &FlowState) -> Result<ProxyStatus> {
    let _ = state;
    let response = service_request(crate::service::ServiceRequest {
        command: "stop".to_string(),
        config: None,
        server_id: None,
        server_name: None,
    })?;
    if response.protocol_version != SERVICE_PROTOCOL_VERSION {
        return Err(anyhow!("root service 版本不匹配，请重新启动代理"));
    }
    let status = proxy_status_from_service(response.status);
    emit_proxy_status(app, &status);
    emit_status(app, "代理", "已向 root service 发送停止请求。");
    Ok(status)
}

fn refresh_proxy_status(state: &FlowState) -> std::result::Result<ProxyStatus, String> {
    let _ = state;
    match service_request(crate::service::ServiceRequest {
        command: "status".to_string(),
        config: None,
        server_id: None,
        server_name: None,
    }) {
        Ok(response) if response.protocol_version == SERVICE_PROTOCOL_VERSION => {
            Ok(proxy_status_from_service(response.status))
        }
        Ok(_) => Ok(ProxyStatus {
            running: false,
            server_id: None,
            server_name: None,
            tun_name: "iwan0".to_string(),
            last_message: None,
            last_error: Some("root service 版本不匹配，请重新启动代理。".to_string()),
        }),
        Err(_) => Ok(ProxyStatus {
            running: false,
            server_id: None,
            server_name: None,
            tun_name: "iwan0".to_string(),
            last_message: None,
            last_error: None,
        }),
    }
}

#[cfg(target_os = "linux")]
fn is_effective_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
fn find_in_path(program: &str) -> Option<PathBuf> {
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|path| path.join(program))
        .find(|path| path.is_file())
}

#[cfg(target_os = "linux")]
fn find_program(program: &str, fixed_paths: &[&str]) -> Option<PathBuf> {
    fixed_paths
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .or_else(|| find_in_path(program))
}

#[cfg(target_os = "linux")]
fn ensure_service_running(app: &AppHandle) -> Result<()> {
    if service_request(ServiceRequest {
        command: "ping".to_string(),
        config: None,
        server_id: None,
        server_name: None,
    })
    .map(|response| response.ok && response.protocol_version == SERVICE_PROTOCOL_VERSION)
    .unwrap_or(false)
    {
        return Ok(());
    }

    emit_status(app, "授权", "正在通过 pkexec 启动 iWAN root service。");
    let mut command = service_command()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().context("启动 root service 失败")?;

    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(45) {
        if service_request(ServiceRequest {
            command: "ping".to_string(),
            config: None,
            server_id: None,
            server_name: None,
        })
        .map(|response| response.ok && response.protocol_version == SERVICE_PROTOCOL_VERSION)
        .unwrap_or(false)
        {
            emit_status(app, "授权", "iWAN root service 已就绪。");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(300));
    }

    Err(anyhow!(
        "root service 未就绪；可能取消了 pkexec 授权，或 service socket 未创建。"
    ))
}

#[cfg(target_os = "linux")]
fn service_command() -> Result<Command> {
    let exe = app_invocation_path();
    let mut command = if is_effective_root() {
        let mut command = Command::new(exe);
        command.arg("--iwan-service");
        command
    } else if let Some(pkexec) = find_program("pkexec", &["/usr/bin/pkexec", "/bin/pkexec"]) {
        let mut command = Command::new(pkexec);
        command.arg(exe).arg("--iwan-service");
        command
    } else {
        return Err(anyhow!("缺少 pkexec，无法启动 root service"));
    };
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(command)
}

#[cfg(target_os = "linux")]
fn app_invocation_path() -> PathBuf {
    env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .or_else(|| env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("/proc/self/exe"))
}

fn service_request(request: ServiceRequest) -> Result<ServiceResponse> {
    let mut stream = UnixStream::connect(SERVICE_SOCKET)
        .with_context(|| format!("无法连接 root service socket: {SERVICE_SOCKET}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let payload = serde_json::to_string(&request)?;
    writeln!(stream, "{payload}")?;

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err(anyhow!("root service 返回空响应"));
    }
    Ok(serde_json::from_str(line.trim())?)
}

fn proxy_status_from_service(status: ServiceStatus) -> ProxyStatus {
    ProxyStatus {
        running: status.proxy_running,
        server_id: status.server_id,
        server_name: status.server_name,
        tun_name: status.tun_name,
        last_message: status.last_message,
        last_error: status.last_error,
    }
}

fn emit_proxy_status(app: &AppHandle, status: &ProxyStatus) {
    let _ = app.emit("iwan-proxy-status", status);
}

fn parse_oauth_callback(raw_url: &str) -> Result<Option<OAuthCallback>> {
    let url = Url::parse(raw_url)?;
    if url.scheme() != REDIRECT_SCHEME || url.host_str() != Some(REDIRECT_HOST) {
        return Ok(None);
    }

    let mut code = None;
    let mut state = None;
    let mut error = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => error = Some(value.into_owned()),
            _ => {}
        }
    }

    if let Some(error) = error {
        return Err(anyhow!("OAuth error: {error}"));
    }

    Ok(Some(OAuthCallback {
        code: code.ok_or_else(|| anyhow!("回调 URL 中缺少 code"))?,
        state: state.ok_or_else(|| anyhow!("回调 URL 中缺少 state"))?,
    }))
}

struct OAuthCallback {
    code: String,
    state: String,
}

fn emit_status(app: &AppHandle, stage: &str, message: &str) {
    let _ = app.emit(
        "iwan-status",
        StatusPayload {
            stage: stage.to_string(),
            message: message.to_string(),
        },
    );
}

fn emit_error(app: &AppHandle, message: &str) {
    let _ = app.emit(
        "iwan-error",
        ErrorPayload {
            message: message.to_string(),
        },
    );
}

fn output_dir(app: &AppHandle) -> Result<PathBuf> {
    Ok(app.path().app_data_dir()?)
}

fn random_urlsafe(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_hex(bytes_len: usize) -> String {
    let mut bytes = vec![0_u8; bytes_len];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn compact_json(value: &Value) -> String {
    let text = serde_json::to_string(value).unwrap_or_else(|_| value.to_string());
    if text.len() > 220 {
        format!("{}...", &text[..220])
    } else {
        text
    }
}

fn preview_token(token: &str) -> String {
    if token.len() <= 16 {
        return "***".to_string();
    }
    format!("{}...{}", &token[..10], &token[token.len() - 6..])
}

#[allow(dead_code)]
fn encryption_salt(device_uuid: &str) -> String {
    sha256_hex(format!("{device_uuid}panabit_config_salt_v1").as_bytes())[..16].to_string()
}

#[allow(dead_code)]
fn decrypt_config(
    encrypted_b64: &str,
    domain: &str,
    file_type: &str,
    version: &str,
    device_uuid: &str,
) -> Result<Value> {
    use base64::engine::general_purpose::STANDARD;

    let salt = encryption_salt(device_uuid);
    let key = Sha256::digest(format!("{domain}{file_type}{version}{FIXED_KEY}{salt}").as_bytes());
    let encrypted = STANDARD.decode(encrypted_b64)?;
    let plain = encrypted
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ key[index % key.len()])
        .collect::<Vec<_>>();
    Ok(serde_json::from_slice(&plain)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_callback_url() {
        let callback =
            parse_oauth_callback("com.panabit.mobile://oauth2redirect?code=abc&state=xyz")
                .unwrap()
                .unwrap();
        assert_eq!(callback.code, "abc");
        assert_eq!(callback.state, "xyz");
    }

    #[test]
    fn canonicalizes_query_like_python_flow() {
        assert_eq!(canonical_query("b=2&a=1"), "a=1&b=2");
        assert_eq!(canonical_query("q=hello%20world"), "q=hello world");
    }

    #[test]
    fn salt_matches_python_algorithm_shape() {
        assert_eq!(encryption_salt("device").len(), 16);
    }
}
