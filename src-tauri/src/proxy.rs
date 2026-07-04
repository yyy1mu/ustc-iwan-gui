use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    os::fd::RawFd,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use md5::Digest;
use serde::{Deserialize, Serialize};

const PT_OPEN_REJECT: u8 = 0x11;
const PT_OPEN_ACK: u8 = 0x12;
const PT_OPEN: u8 = 0x13;
const PT_DATA: u8 = 0x14;
const PT_CLOSE: u8 = 0x17;
const PT_DATA_ENC: u8 = 0x18;

const T_USERNAME: u8 = 0x01;
const T_PASSWORD: u8 = 0x02;
const T_MTU: u8 = 0x03;
const T_IP: u8 = 0x04;
const T_DNS: u8 = 0x05;
const T_GATEWAY: u8 = 0x06;
const T_ENCRYPT: u8 = 0x08;
const T_AUTH_VERIFY: u8 = 0x0f;

const TUNSETIFF: u64 = 0x400454ca;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const DNS_RESOLVER: &str = "114.114.114.114:53";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub encrypt: u8,
    pub mtu: u16,
    pub tun_name: String,
    #[serde(default)]
    pub route_hosts: Vec<String>,
    #[serde(default)]
    pub route_cidr: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyIpcMessage {
    pub kind: String,
    pub stage: String,
    pub message: String,
    pub running: Option<bool>,
    pub tun_name: Option<String>,
}

struct ProxyIpc {
    stream: Option<UnixStream>,
}

impl ProxyIpc {
    fn connect(path: Option<PathBuf>) -> Self {
        let stream = path.and_then(|path| UnixStream::connect(path).ok());
        Self { stream }
    }

    fn log(&mut self, stage: &str, message: &str) {
        self.send("log", stage, message, None, None);
    }

    fn status(&mut self, stage: &str, message: &str, running: bool, tun_name: &str) {
        self.send(
            "status",
            stage,
            message,
            Some(running),
            Some(tun_name.to_string()),
        );
    }

    fn error(&mut self, message: &str) {
        self.send("error", "代理", message, Some(false), None);
    }

    fn send(
        &mut self,
        kind: &str,
        stage: &str,
        message: &str,
        running: Option<bool>,
        tun_name: Option<String>,
    ) {
        let Some(stream) = self.stream.as_mut() else {
            return;
        };
        let payload = ProxyIpcMessage {
            kind: kind.to_string(),
            stage: stage.to_string(),
            message: message.to_string(),
            running,
            tun_name,
        };
        if let Ok(line) = serde_json::to_string(&payload) {
            let _ = writeln!(stream, "{line}");
            let _ = stream.flush();
        }
    }
}

pub fn run_proxy_process() -> ! {
    let (config, ipc_path) = match read_config_from_args() {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let mut ipc = ProxyIpc::connect(ipc_path);
    ipc.log("授权", "root 代理进程已启动。");

    let code = match run_proxy(config, &mut ipc) {
        Ok(()) => {
            ipc.status("代理", "代理进程已退出。", false, "iwan0");
            0
        }
        Err(err) => {
            ipc.error(&err);
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(code);
}

fn read_config_from_args() -> Result<(ProxyConfig, Option<PathBuf>), String> {
    let mut args = std::env::args().skip(2);
    let mut config_path = None;
    let mut ipc_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_path = args.next().map(PathBuf::from),
            "--ipc" => ipc_path = args.next().map(PathBuf::from),
            other => return Err(format!("unknown proxy arg: {other}")),
        }
    }

    let path = config_path.ok_or_else(|| "missing --config".to_string())?;
    let bytes = fs::read(&path).map_err(|err| format!("read {}: {err}", path.display()))?;
    let config =
        serde_json::from_slice(&bytes).map_err(|err| format!("parse {}: {err}", path.display()))?;
    Ok((config, ipc_path))
}

fn md5(data: &[u8]) -> [u8; 16] {
    let digest = md5::Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn encrypt_password(plain: &str, username: &str) -> [u8; 16] {
    let key = md5([b"mw", username.as_bytes()].concat().as_slice());
    let mut pt = [0u8; 16];
    let password_bytes = plain.as_bytes();
    pt[..password_bytes.len().min(16)]
        .copy_from_slice(&password_bytes[..password_bytes.len().min(16)]);
    let cipher = Aes128::new(GenericArray::from_slice(&key));
    let mut block = GenericArray::clone_from_slice(&pt);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

fn session_key(username: &str, password: &str) -> [u8; 16] {
    md5([username.as_bytes(), password.as_bytes()]
        .concat()
        .as_slice())
}

fn xor_inplace(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for index in 0..data.len() {
        data[index] ^= key[index % key.len()];
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn nonce() -> Result<u32, String> {
    let mut bytes = [0u8; 4];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|err| format!("nonce: {err}"))?;
    Ok(u32::from_le_bytes(bytes))
}

fn pkhdr(packet_type: u8, enc: u8, sid: u16, token: u32) -> [u8; 8] {
    let mut header = [0u8; 8];
    header[0] = packet_type;
    header[1] = enc;
    header[2..4].copy_from_slice(&sid.to_be_bytes());
    header[4..8].copy_from_slice(&token.to_be_bytes());
    header
}

fn sig8(header: &[u8]) -> [u8; 16] {
    let mut bytes = [0u8; 10];
    bytes[..8].copy_from_slice(header);
    bytes[8..].copy_from_slice(b"mw");
    md5(&bytes)
}

fn ctrl(header: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    [header.as_slice(), &sig8(header), payload].concat()
}

fn data(header: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    [header.as_slice(), payload].concat()
}

fn tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + value.len());
    out.push(tlv_type);
    out.push((value.len() + 2) as u8);
    out.extend_from_slice(value);
    out
}

fn parse_tlvs(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    let mut index = 0;
    while index + 2 <= bytes.len() {
        let tlv_type = bytes[index];
        let len = bytes[index + 1] as usize;
        if len < 2 || index + len > bytes.len() {
            break;
        }
        out.push((tlv_type, bytes[index + 2..index + len].to_vec()));
        index += len;
    }
    out
}

fn verify_sig(buffer: &[u8]) -> bool {
    buffer.len() >= 24 && sig8(&buffer[..8]) == buffer[8..24]
}

fn ip_to_string(bytes: &[u8]) -> String {
    if bytes.len() < 4 {
        "0.0.0.0".to_string()
    } else {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

fn build_open(
    username: &str,
    encrypted_password: &[u8; 16],
    mtu: u16,
    enc: u8,
    nonce: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(tlv(T_MTU, &mtu.to_be_bytes()));
    payload.extend(tlv(T_USERNAME, username.as_bytes()));
    payload.extend(tlv(T_PASSWORD, encrypted_password));
    payload.extend(tlv(T_ENCRYPT, &[enc]));
    payload.extend(tlv(T_AUTH_VERIFY, &nonce.to_be_bytes()));
    let header = pkhdr(PT_OPEN, enc, 0, 0);
    ctrl(&header, &payload)
}

struct Auth {
    sid: u16,
    token: u32,
    tun_ip: String,
    gateway: String,
    dns: String,
    mtu: u16,
}

fn parse_ack(buffer: &[u8], expect_nonce: u32) -> Result<Auth, String> {
    if buffer.len() < 24 {
        return Err("OPEN_ACK too short".to_string());
    }

    let packet_type = buffer[0];
    let sid = u16::from_be_bytes([buffer[2], buffer[3]]);
    let token = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);

    if packet_type == PT_OPEN_REJECT {
        return Err(format!(
            "OPEN_REJECT: {}",
            String::from_utf8_lossy(&buffer[24..])
        ));
    }
    if packet_type != PT_OPEN_ACK {
        return Err(format!(
            "unexpected packet type 0x{packet_type:02x}, payload={}",
            hex(&buffer[24..])
        ));
    }
    if !verify_sig(buffer) {
        return Err("bad OPEN_ACK signature".to_string());
    }

    let mut tun_ip = String::new();
    let mut gateway = String::new();
    let mut dns = String::new();
    let mut mtu = 1400;
    let mut auth_verified = false;

    for (tlv_type, value) in parse_tlvs(&buffer[24..]) {
        match tlv_type {
            T_IP => tun_ip = ip_to_string(&value),
            T_GATEWAY => gateway = ip_to_string(&value),
            T_DNS => dns = ip_to_string(&value),
            T_MTU if value.len() >= 2 => mtu = u16::from_be_bytes([value[0], value[1]]),
            T_AUTH_VERIFY => {
                if value.len() != 4 {
                    return Err("AUTH_VERIFY wrong length".to_string());
                }
                let echo = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                if echo != expect_nonce {
                    return Err(format!("AUTH_VERIFY mismatch {echo:08x}"));
                }
                auth_verified = true;
            }
            _ => {}
        }
    }

    if !auth_verified {
        eprintln!("server did not echo AUTH_VERIFY");
    }

    Ok(Auth {
        sid,
        token,
        tun_ip,
        gateway,
        dns,
        mtu,
    })
}

fn udp_connect(host: &str, port: u16, timeout_ms: u64) -> std::io::Result<UdpSocket> {
    let addr: SocketAddr = format!("{host}:{port}")
        .parse()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    Ok(socket)
}

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    flags: u16,
}

fn open_tun(name: &str) -> std::io::Result<RawFd> {
    let path = std::ffi::CString::new("/dev/net/tun").expect("static tun path");
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut ifr = Ifreq {
        name: [0u8; 16],
        flags: IFF_TUN | IFF_NO_PI,
    };
    let name_bytes = name.as_bytes();
    ifr.name[..name_bytes.len().min(15)].copy_from_slice(&name_bytes[..name_bytes.len().min(15)]);

    if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) } < 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err);
    }

    Ok(fd)
}

fn set_nonblock(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags >= 0 {
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn ip_command() -> Command {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Command::new(path);
        }
    }
    Command::new("ip")
}

fn ip(args: &[&str]) -> bool {
    ip_command()
        .args(args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn capture_default_route() -> Option<(String, String)> {
    let output = ip_command()
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let mut gateway = None;
        let mut device = None;
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "via" {
                gateway = words.next().map(ToOwned::to_owned);
            }
            if word == "dev" {
                device = words.next().map(ToOwned::to_owned);
            }
        }
        if let (Some(gateway), Some(device)) = (gateway, device) {
            return Some((gateway, device));
        }
    }

    None
}

#[derive(Debug, Clone)]
struct RouteChange {
    target: String,
    original: Option<String>,
}

struct RouteSetup {
    installed_routes: Vec<String>,
    changes: Vec<RouteChange>,
}

fn route_device(destination: &str) -> Option<String> {
    let output = ip_command()
        .args(["-4", "route", "get", destination])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut words = text.split_whitespace();
    while let Some(word) = words.next() {
        if word == "dev" {
            return words.next().map(ToOwned::to_owned);
        }
    }
    None
}

fn exact_route(target: &str) -> Option<String> {
    let output = ip_command()
        .args(["-4", "route", "show", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToOwned::to_owned)
}

fn replace_route_with_restore(
    changes: &mut Vec<RouteChange>,
    target: &str,
    route_args: &[&str],
) -> bool {
    let original = exact_route(target);
    let ok = ip_command()
        .arg("route")
        .arg("replace")
        .arg(target)
        .args(route_args)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if ok {
        changes.push(RouteChange {
            target: target.to_string(),
            original,
        });
    }
    ok
}

fn restore_route(change: &RouteChange) {
    if let Some(original) = change.original.as_deref() {
        let args = original.split_whitespace().collect::<Vec<_>>();
        let _ = ip_command().arg("route").arg("replace").args(args).status();
    } else {
        let _ = ip(&["route", "del", &change.target]);
    }
}

fn dns_query_a(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    let name = host.trim().trim_end_matches('.');
    if name.is_empty() {
        return Ok(Vec::new());
    }

    let query_id = name
        .as_bytes()
        .iter()
        .fold(std::process::id() as u16, |acc, byte| {
            acc.rotate_left(5) ^ u16::from(*byte)
        });

    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&query_id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());

    for label in name.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("invalid DNS label in {host}"));
        }
        packet.push(bytes.len() as u8);
        packet.extend_from_slice(bytes);
    }
    packet.push(0);
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| format!("dns bind: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|err| format!("dns timeout: {err}"))?;
    socket
        .send_to(&packet, DNS_RESOLVER)
        .map_err(|err| format!("dns send {host}: {err}"))?;

    let mut response = [0u8; 1500];
    let (size, _) = socket
        .recv_from(&mut response)
        .map_err(|err| format!("dns recv {host}: {err}"))?;
    parse_dns_a_response(&response[..size], query_id)
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let len = *packet.get(offset)?;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xc0 == 0xc0 {
            packet.get(offset + 1)?;
            return Some(offset + 2);
        }
        if len & 0xc0 != 0 {
            return None;
        }
        offset = offset.checked_add(1 + usize::from(len))?;
        if offset > packet.len() {
            return None;
        }
    }
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

fn parse_dns_a_response(packet: &[u8], query_id: u16) -> Result<Vec<Ipv4Addr>, String> {
    if packet.len() < 12 {
        return Err("dns response too short".to_string());
    }
    if read_u16(packet, 0) != Some(query_id) {
        return Err("dns response id mismatch".to_string());
    }

    let flags = read_u16(packet, 2).unwrap_or(0);
    if flags & 0x000f != 0 {
        return Err(format!("dns server returned rcode {}", flags & 0x000f));
    }

    let qdcount = read_u16(packet, 4).unwrap_or(0);
    let ancount = read_u16(packet, 6).unwrap_or(0);
    let mut offset = 12usize;

    for _ in 0..qdcount {
        offset = skip_dns_name(packet, offset).ok_or_else(|| "invalid dns question".to_string())?;
        offset = offset
            .checked_add(4)
            .ok_or_else(|| "invalid dns question".to_string())?;
        if offset > packet.len() {
            return Err("truncated dns question".to_string());
        }
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        offset = skip_dns_name(packet, offset).ok_or_else(|| "invalid dns answer".to_string())?;
        if offset + 10 > packet.len() {
            return Err("truncated dns answer".to_string());
        }
        let record_type = read_u16(packet, offset).unwrap_or(0);
        let class = read_u16(packet, offset + 2).unwrap_or(0);
        let data_len = read_u16(packet, offset + 8).unwrap_or(0) as usize;
        offset += 10;
        if offset + data_len > packet.len() {
            return Err("truncated dns record data".to_string());
        }
        if record_type == 1 && class == 1 && data_len == 4 {
            addrs.push(Ipv4Addr::new(
                packet[offset],
                packet[offset + 1],
                packet[offset + 2],
                packet[offset + 3],
            ));
        }
        offset += data_len;
    }

    Ok(addrs)
}

fn resolve_host_routes(hosts: &[String]) -> Vec<String> {
    let mut routes = BTreeSet::new();
    for host in hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            routes.insert(format!("{ip}/32"));
            continue;
        }

        match dns_query_a(host) {
            Ok(addrs) => {
                for ip in addrs {
                    routes.insert(format!("{ip}/32"));
                }
            }
            Err(err) => eprintln!("dns query {host} via {DNS_RESOLVER}: {err}"),
        }

        match (host, 443).to_socket_addrs() {
            Ok(addrs) => {
                for addr in addrs {
                    if let std::net::IpAddr::V4(ip) = addr.ip() {
                        routes.insert(format!("{ip}/32"));
                    }
                }
            }
            Err(err) => eprintln!("system dns query {host}: {err}"),
        }
    }
    routes.into_iter().collect()
}

fn setup_routes(
    tun_name: &str,
    auth: &Auth,
    server: &str,
    old_gateway: &str,
    old_device: &str,
    cidr: Option<&str>,
    route_hosts: &[String],
) -> RouteSetup {
    let _ = ip(&["addr", "flush", "dev", tun_name]);
    ip(&["link", "set", tun_name, "up"]);
    ip(&["link", "set", "dev", tun_name, "mtu", &auth.mtu.to_string()]);
    ip(&[
        "addr",
        "add",
        &format!("{}/24", auth.tun_ip),
        "dev",
        tun_name,
    ]);

    let mut changes = Vec::new();
    replace_route_with_restore(
        &mut changes,
        &format!("{server}/32"),
        &["via", old_gateway, "dev", old_device],
    );
    ip(&["route", "flush", "cache"]);

    let mut installed_routes = Vec::new();
    if let Some(cidr) = cidr {
        if cidr != "default" && cidr != "0.0.0.0/0" {
            if replace_route_with_restore(&mut changes, cidr, &["dev", tun_name]) {
                installed_routes.push(cidr.to_string());
            }
        }
    }

    for route in resolve_host_routes(route_hosts) {
        if replace_route_with_restore(&mut changes, &route, &["dev", tun_name]) {
            installed_routes.push(route);
        }
    }
    ip(&["route", "flush", "cache"]);
    RouteSetup {
        installed_routes,
        changes,
    }
}

fn teardown(tun_name: &str, route_setup: &RouteSetup) {
    for change in route_setup.changes.iter().rev() {
        restore_route(change);
    }
    let _ = ip(&["addr", "flush", "dev", tun_name]);
    let _ = ip(&["link", "set", tun_name, "down"]);
    let _ = ip(&["route", "flush", "cache"]);
}

fn tun_read(fd: RawFd, buffer: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buffer.as_mut_ptr() as _, buffer.len()) }
}

fn tun_write(fd: RawFd, buffer: &[u8]) -> isize {
    unsafe { libc::write(fd, buffer.as_ptr() as _, buffer.len()) }
}

fn run_proxy(config: ProxyConfig, ipc: &mut ProxyIpc) -> Result<(), String> {
    validate_root_requirements()?;
    ipc.log("检查", "root 权限和 TUN 环境检查通过。");

    let encrypted_password = encrypt_password(&config.password, &config.username);
    let auth_nonce = nonce()?;
    let open_packet = build_open(
        &config.username,
        &encrypted_password,
        config.mtu,
        config.encrypt,
        auth_nonce,
    );

    ipc.log("代理", "正在连接 SDWAN 节点。");
    let socket =
        udp_connect(&config.server, config.port, 3000).map_err(|err| format!("udp: {err}"))?;
    let auth = {
        let mut result = None;
        for attempt in 0u32..=3 {
            socket
                .send(&open_packet)
                .map_err(|err| format!("send OPEN: {err}"))?;
            ipc.log("代理", "正在与 SDWAN 节点握手。");
            println!("[{attempt}] OPEN sent");
            let mut buffer = [0u8; 4096];
            match socket.recv(&mut buffer) {
                Ok(size) => match parse_ack(&buffer[..size], auth_nonce) {
                    Ok(auth) => {
                        result = Some(auth);
                        break;
                    }
                    Err(err) => eprintln!("[{attempt}] {err}"),
                },
                Err(err) => eprintln!("[{attempt}] timeout: {err}"),
            }
            std::thread::sleep(Duration::from_millis(1000));
        }
        result.ok_or_else(|| "auth failed".to_string())?
    };

    println!(
        "auth OK sid={:#06x} token={:#010x} tun={} gw={} dns={} mtu={}",
        auth.sid, auth.token, auth.tun_ip, auth.gateway, auth.dns, auth.mtu
    );
    ipc.log("代理", "SDWAN 节点认证成功。");

    if config.encrypt != 1 {
        eprintln!(
            "WARN: data plane supports XOR encrypt=1, got {}",
            config.encrypt
        );
    }
    let xk = session_key(&config.username, &config.password)[..8].to_vec();

    let (old_gateway, old_device) =
        capture_default_route().ok_or_else(|| "cannot detect default route".to_string())?;
    println!("original route via {old_gateway} dev {old_device}");
    ipc.log("代理", "已记录原默认路由。");

    let _ = ip(&["link", "del", &config.tun_name]);
    let tun = open_tun(&config.tun_name).map_err(|err| format!("open tun: {err}"))?;
    set_nonblock(tun);
    println!("tun {} opened", config.tun_name);
    ipc.log("代理", "TUN 网卡已创建。");

    ipc.log("DNS", "正在使用 114.114.114.114 和系统 DNS 查询 LLM 域名。");
    let route_setup = setup_routes(
        &config.tun_name,
        &auth,
        &config.server,
        &old_gateway,
        &old_device,
        config.route_cidr.as_deref(),
        &config.route_hosts,
    );
    println!("tun {} up", config.tun_name);
    ipc.log("代理", "TUN 网卡已启用，未接管默认路由。");

    if route_setup.installed_routes.is_empty() {
        ipc.log("路由", "未解析到 LLM 域名 IPv4 地址，未安装 TUN 业务路由。");
    } else {
        ipc.log(
            "路由",
            &format!(
                "已安装 LLM TUN 路由：{}",
                route_setup.installed_routes.join(", ")
            ),
        );
    }

    for route in &route_setup.installed_routes {
        let check_ip = route.strip_suffix("/32").unwrap_or(route);
        match route_device(check_ip) {
            Some(device) if device == config.tun_name => {
                ipc.log("路由", &format!("{check_ip} 已指向 TUN。"));
            }
            Some(device) => {
                ipc.log(
                    "路由",
                    &format!("{check_ip} 当前走 {device}，请检查系统路由策略。"),
                );
            }
            None => {
                ipc.log("路由", &format!("无法确认 {check_ip} 路由。"));
            }
        }
    }

    let running = Arc::new(AtomicBool::new(true));
    let socket_send = socket
        .try_clone()
        .map_err(|err| format!("clone udp send socket: {err}"))?;
    let socket_recv = socket
        .try_clone()
        .map_err(|err| format!("clone udp recv socket: {err}"))?;
    socket_recv
        .set_read_timeout(Some(Duration::from_millis(300)))
        .ok();

    let tun_to_udp_running = running.clone();
    let udp_to_tun_running = running.clone();
    let xk_to_udp = xk.clone();
    let xk_to_tun = xk;
    let sid = auth.sid;
    let token = auth.token;
    let enc = config.encrypt;
    let tun_read_packets = Arc::new(AtomicU64::new(0));
    let tun_read_bytes = Arc::new(AtomicU64::new(0));
    let udp_send_packets = Arc::new(AtomicU64::new(0));
    let udp_recv_packets = Arc::new(AtomicU64::new(0));
    let udp_recv_bytes = Arc::new(AtomicU64::new(0));
    let tun_write_packets = Arc::new(AtomicU64::new(0));
    let tun_write_bytes = Arc::new(AtomicU64::new(0));
    let tun_read_packets_worker = tun_read_packets.clone();
    let tun_read_bytes_worker = tun_read_bytes.clone();
    let udp_send_packets_worker = udp_send_packets.clone();
    let udp_recv_packets_worker = udp_recv_packets.clone();
    let udp_recv_bytes_worker = udp_recv_bytes.clone();
    let tun_write_packets_worker = tun_write_packets.clone();
    let tun_write_bytes_worker = tun_write_bytes.clone();

    let tun_to_udp = std::thread::spawn(move || {
        let mut buffer = vec![0u8; 2048];
        println!("tun-to-udp started");
        loop {
            if !tun_to_udp_running.load(Ordering::Relaxed) {
                break;
            }
            let size = tun_read(tun, &mut buffer);
            if size == -1 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                eprintln!("tun read: {err}");
                tun_to_udp_running.store(false, Ordering::Relaxed);
                break;
            }
            if size <= 0 {
                tun_to_udp_running.store(false, Ordering::Relaxed);
                break;
            }

            let packet = &mut buffer[..size as usize];
            tun_read_packets_worker.fetch_add(1, Ordering::Relaxed);
            tun_read_bytes_worker.fetch_add(size as u64, Ordering::Relaxed);
            xor_inplace(packet, &xk_to_udp);
            let header = pkhdr(PT_DATA_ENC, enc, sid, token);
            if socket_send.send(&data(&header, packet)).is_err() {
                tun_to_udp_running.store(false, Ordering::Relaxed);
                break;
            }
            udp_send_packets_worker.fetch_add(1, Ordering::Relaxed);
        }
        println!("tun-to-udp stopped");
    });

    let udp_to_tun = std::thread::spawn(move || {
        let mut buffer = vec![0u8; 65535];
        println!("udp-to-tun started");
        loop {
            if !udp_to_tun_running.load(Ordering::Relaxed) {
                break;
            }
            match socket_recv.recv(&mut buffer) {
                Ok(size) if size >= 8 => {
                    udp_recv_packets_worker.fetch_add(1, Ordering::Relaxed);
                    udp_recv_bytes_worker.fetch_add(size as u64, Ordering::Relaxed);
                    let packet_type = buffer[0];
                    if packet_type == PT_DATA_ENC {
                        xor_inplace(&mut buffer[8..size], &xk_to_tun);
                        let written = tun_write(tun, &buffer[8..size]);
                        if written > 0 {
                            tun_write_packets_worker.fetch_add(1, Ordering::Relaxed);
                            tun_write_bytes_worker.fetch_add(written as u64, Ordering::Relaxed);
                        }
                    } else if packet_type == PT_DATA {
                        let written = tun_write(tun, &buffer[8..size]);
                        if written > 0 {
                            tun_write_packets_worker.fetch_add(1, Ordering::Relaxed);
                            tun_write_bytes_worker.fetch_add(written as u64, Ordering::Relaxed);
                        }
                    } else if packet_type == PT_CLOSE {
                        eprintln!("server sent CLOSE");
                        udp_to_tun_running.store(false, Ordering::Relaxed);
                        break;
                    }
                }
                Ok(_) => {}
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut => {}
                Err(err) => {
                    eprintln!("udp recv: {err}");
                    udp_to_tun_running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        println!("udp-to-tun stopped");
    });

    let signal_running = running.clone();
    ctrlc::set_handler(move || {
        eprintln!("shutdown signal received");
        signal_running.store(false, Ordering::Relaxed);
    })
    .map_err(|err| format!("signal handler: {err}"))?;

    println!("proxy running");
    ipc.status("代理", "代理进程运行中。", true, &config.tun_name);
    let mut last_stats = Instant::now();
    while running.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(200));
        if last_stats.elapsed() >= Duration::from_secs(5) {
            last_stats = Instant::now();
            ipc.log(
                "数据面",
                &format!(
                    "TUN->UDP {}包/{}字节，UDP->TUN {}包/{}字节，写回TUN {}包/{}字节。",
                    tun_read_packets.load(Ordering::Relaxed),
                    tun_read_bytes.load(Ordering::Relaxed),
                    udp_recv_packets.load(Ordering::Relaxed),
                    udp_recv_bytes.load(Ordering::Relaxed),
                    tun_write_packets.load(Ordering::Relaxed),
                    tun_write_bytes.load(Ordering::Relaxed),
                ),
            );
        }
    }

    tun_to_udp.join().ok();
    udp_to_tun.join().ok();

    teardown(&config.tun_name, &route_setup);

    let close_header = pkhdr(PT_CLOSE, enc, sid, token);
    let _ = socket.send(&ctrl(&close_header, &[]));
    unsafe {
        libc::close(tun);
    }
    println!("proxy stopped");
    ipc.status("代理", "代理进程已清理并退出。", false, &config.tun_name);
    Ok(())
}

fn validate_root_requirements() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("代理 helper 未获得 root 权限，无法创建 TUN 网卡。".to_string());
    }
    if !PathBuf::from("/dev/net/tun").exists() {
        return Err("缺少 /dev/net/tun，请加载 tun 模块后重试。".to_string());
    }
    let ip_ok = ip_command()
        .arg("-V")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !ip_ok {
        return Err("缺少 iproute2 的 ip 命令，无法配置 TUN 网卡和路由。".to_string());
    }
    Ok(())
}
