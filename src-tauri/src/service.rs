use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::proxy::{ProxyConfig, ProxyIpcMessage};

pub const SERVICE_DIR: &str = "/tmp/ustc-iwan";
pub const SERVICE_SOCKET: &str = "/tmp/ustc-iwan/iwan-service.sock";
pub const SERVICE_PROTOCOL_VERSION: u32 = 5;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRequest {
    pub command: String,
    pub config: Option<ProxyConfig>,
    pub server_id: Option<usize>,
    pub server_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServiceStatus {
    pub service_running: bool,
    pub proxy_running: bool,
    pub server_id: Option<usize>,
    pub server_name: Option<String>,
    pub tun_name: String,
    pub last_message: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceResponse {
    pub protocol_version: u32,
    pub ok: bool,
    pub message: String,
    pub status: ServiceStatus,
}

struct ServiceState {
    proxy: Option<ManagedProxy>,
    status: ServiceStatus,
}

struct ManagedProxy {
    child: Child,
    config_path: PathBuf,
    ipc_path: PathBuf,
}

pub fn run_service_process() -> ! {
    let code = match run_service() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(code);
}

fn run_service() -> Result<(), String> {
    validate_service_environment()?;
    fs::create_dir_all(SERVICE_DIR).map_err(|err| format!("create {SERVICE_DIR}: {err}"))?;
    fs::set_permissions(SERVICE_DIR, fs::Permissions::from_mode(0o777))
        .map_err(|err| format!("chmod {SERVICE_DIR}: {err}"))?;
    let _ = fs::remove_file(SERVICE_SOCKET);

    let listener = UnixListener::bind(SERVICE_SOCKET)
        .map_err(|err| format!("bind {SERVICE_SOCKET}: {err}"))?;
    fs::set_permissions(SERVICE_SOCKET, fs::Permissions::from_mode(0o666))
        .map_err(|err| format!("chmod {SERVICE_SOCKET}: {err}"))?;

    let state = Arc::new(Mutex::new(ServiceState {
        proxy: None,
        status: ServiceStatus {
            service_running: true,
            proxy_running: false,
            server_id: None,
            server_name: None,
            tun_name: "iwan0".to_string(),
            last_message: Some("root service 已启动。".to_string()),
            last_error: None,
        },
    }));

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = state.clone();
                thread::spawn(move || {
                    let _ = handle_client(stream, state);
                });
            }
            Err(err) => eprintln!("accept service client: {err}"),
        }
    }

    Ok(())
}

fn handle_client(mut stream: UnixStream, state: Arc<Mutex<ServiceState>>) -> Result<(), String> {
    let mut line = String::new();
    BufReader::new(stream.try_clone().map_err(|err| err.to_string())?)
        .read_line(&mut line)
        .map_err(|err| format!("read request: {err}"))?;
    let request: ServiceRequest =
        serde_json::from_str(line.trim()).map_err(|err| format!("parse request: {err}"))?;

    let response = match request.command.as_str() {
        "ping" => ServiceResponse {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            ok: true,
            message: "service ready".to_string(),
            status: refresh_status(&state),
        },
        "status" => ServiceResponse {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            ok: true,
            message: "status".to_string(),
            status: refresh_status(&state),
        },
        "start" => start_proxy(request, &state),
        "stop" => stop_proxy(&state),
        other => ServiceResponse {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            ok: false,
            message: format!("unknown command: {other}"),
            status: refresh_status(&state),
        },
    };

    let payload = serde_json::to_string(&response).map_err(|err| err.to_string())?;
    writeln!(stream, "{payload}").map_err(|err| format!("write response: {err}"))?;
    Ok(())
}

fn start_proxy(request: ServiceRequest, state: &Arc<Mutex<ServiceState>>) -> ServiceResponse {
    if let Err(err) = validate_service_environment() {
        return error_response(state, err);
    }
    let Some(config) = request.config else {
        return error_response(state, "missing proxy config".to_string());
    };

    let _ = stop_proxy_inner(state);

    let config_path = PathBuf::from(SERVICE_DIR).join("iwan-proxy.json");
    if let Err(err) = fs::write(
        &config_path,
        serde_json::to_vec(&config).unwrap_or_default(),
    ) {
        return error_response(state, format!("write proxy config: {err}"));
    }
    let _ = fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600));

    let ipc_path = PathBuf::from(SERVICE_DIR).join("iwan-proxy-ipc.sock");
    let _ = fs::remove_file(&ipc_path);
    let listener = match UnixListener::bind(&ipc_path) {
        Ok(listener) => listener,
        Err(err) => return error_response(state, format!("bind proxy IPC: {err}")),
    };
    let _ = fs::set_permissions(&ipc_path, fs::Permissions::from_mode(0o600));

    let exe = service_executable();
    let mut command = Command::new(exe);
    command
        .arg("--iwan-proxy")
        .arg("--config")
        .arg(&config_path)
        .arg("--ipc")
        .arg(&ipc_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return error_response(state, format!("spawn proxy: {err}")),
    };

    {
        let mut state = state.lock().expect("service state poisoned");
        state.status.proxy_running = false;
        state.status.server_id = request.server_id;
        state.status.server_name = request.server_name.clone();
        state.status.tun_name = config.tun_name.clone();
        state.status.last_message = Some("代理进程已启动，等待 TUN 握手。".to_string());
        state.status.last_error = None;
        state.proxy = Some(ManagedProxy {
            child,
            config_path,
            ipc_path: ipc_path.clone(),
        });
    }

    spawn_proxy_ipc_reader(listener, state.clone());
    ServiceResponse {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        ok: true,
        message: "proxy starting".to_string(),
        status: refresh_status(state),
    }
}

fn stop_proxy(state: &Arc<Mutex<ServiceState>>) -> ServiceResponse {
    match stop_proxy_inner(state) {
        Ok(()) => ServiceResponse {
            protocol_version: SERVICE_PROTOCOL_VERSION,
            ok: true,
            message: "proxy stopped".to_string(),
            status: refresh_status(state),
        },
        Err(err) => error_response(state, err),
    }
}

fn stop_proxy_inner(state: &Arc<Mutex<ServiceState>>) -> Result<(), String> {
    let mut proxy = {
        let mut state = state.lock().expect("service state poisoned");
        state.proxy.take()
    };

    if let Some(proxy) = proxy.as_mut() {
        terminate_proxy(proxy)?;
        let _ = fs::remove_file(&proxy.config_path);
        let _ = fs::remove_file(&proxy.ipc_path);
    }

    let mut state = state.lock().expect("service state poisoned");
    state.status.proxy_running = false;
    state.status.server_id = None;
    state.status.server_name = None;
    state.status.last_message = Some("代理已停止。".to_string());
    Ok(())
}

fn refresh_status(state: &Arc<Mutex<ServiceState>>) -> ServiceStatus {
    let mut state_guard = state.lock().expect("service state poisoned");
    if let Some(proxy) = state_guard.proxy.as_mut() {
        match proxy.child.try_wait() {
            Ok(Some(status)) => {
                let config_path = proxy.config_path.clone();
                let ipc_path = proxy.ipc_path.clone();
                state_guard.proxy = None;
                state_guard.status.proxy_running = false;
                state_guard.status.server_id = None;
                state_guard.status.server_name = None;
                state_guard.status.last_message = Some(format!("代理进程已退出: {status}"));
                let _ = fs::remove_file(config_path);
                let _ = fs::remove_file(ipc_path);
            }
            Ok(None) => {}
            Err(err) => {
                state_guard.status.proxy_running = false;
                state_guard.status.last_error = Some(format!("读取代理状态失败: {err}"));
            }
        }
    }
    state_guard.status.clone()
}

fn spawn_proxy_ipc_reader(listener: UnixListener, state: Arc<Mutex<ServiceState>>) {
    thread::spawn(move || {
        let stream = match listener.accept() {
            Ok((stream, _addr)) => stream,
            Err(err) => {
                let mut state = state.lock().expect("service state poisoned");
                state.status.proxy_running = false;
                state.status.last_error = Some(format!("代理 IPC 连接失败: {err}"));
                return;
            }
        };

        for line in BufReader::new(stream)
            .lines()
            .map_while(std::result::Result::ok)
        {
            if let Ok(message) = serde_json::from_str::<ProxyIpcMessage>(&line) {
                let mut state = state.lock().expect("service state poisoned");
                match message.kind.as_str() {
                    "log" => state.status.last_message = Some(message.message),
                    "status" => {
                        state.status.proxy_running =
                            message.running.unwrap_or(state.status.proxy_running);
                        state.status.last_message = Some(message.message);
                        if let Some(tun_name) = message.tun_name {
                            state.status.tun_name = tun_name;
                        }
                    }
                    "error" => {
                        state.status.proxy_running = false;
                        state.status.last_error = Some(message.message);
                    }
                    _ => {}
                }
            }
        }
    });
}

fn error_response(state: &Arc<Mutex<ServiceState>>, message: String) -> ServiceResponse {
    {
        let mut state = state.lock().expect("service state poisoned");
        state.status.last_error = Some(message.clone());
        state.status.proxy_running = false;
    }
    ServiceResponse {
        protocol_version: SERVICE_PROTOCOL_VERSION,
        ok: false,
        message,
        status: refresh_status(state),
    }
}

fn terminate_proxy(proxy: &mut ManagedProxy) -> Result<(), String> {
    let pid = proxy.child.id() as i32;
    unsafe {
        libc::kill(-pid, libc::SIGINT);
    }
    for _ in 0..50 {
        match proxy.child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(err) => return Err(format!("wait proxy: {err}")),
        }
    }
    proxy
        .child
        .kill()
        .map_err(|err| format!("kill proxy: {err}"))?;
    let _ = proxy.child.wait();
    Ok(())
}

fn validate_service_environment() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("iWAN service 必须以 root 权限运行。".to_string());
    }
    if !Path::new("/dev/net/tun").exists() {
        return Err("缺少 /dev/net/tun，请加载 tun 模块。".to_string());
    }
    let ip_ok = ip_command()
        .arg("-V")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !ip_ok {
        return Err("缺少 iproute2 的 ip 命令。".to_string());
    }
    Ok(())
}

fn ip_command() -> Command {
    for path in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        if Path::new(path).is_file() {
            return Command::new(path);
        }
    }
    Command::new("ip")
}

fn service_executable() -> PathBuf {
    std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .or_else(|| std::env::current_exe().ok())
        .unwrap_or_else(|| PathBuf::from("/proc/self/exe"))
}
