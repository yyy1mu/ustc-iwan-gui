import "./styles.css";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const loginButton = document.querySelector("#loginButton");
const stopProxyButton = document.querySelector("#stopProxyButton");
const clearLogButton = document.querySelector("#clearLogButton");
const stageBadge = document.querySelector("#stageBadge");
const resultBadge = document.querySelector("#resultBadge");
const deviceUuid = document.querySelector("#deviceUuid");
const callbackState = document.querySelector("#callbackState");
const proxyState = document.querySelector("#proxyState");
const serverList = document.querySelector("#serverList");
const logList = document.querySelector("#logList");

let proxyStatus = { running: false, serverId: null, serverName: null, tunName: "iwan0" };
let lastServers = [];
let lastProxyNotice = "";

function appendLog(stage, message, kind = "info") {
  const item = document.createElement("li");
  item.className = `log-item ${kind}`;
  const time = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  item.innerHTML = `<span>${time}</span><strong>${stage}</strong><p>${message}</p>`;
  logList.prepend(item);
}

function setBusy(isBusy) {
  loginButton.disabled = isBusy;
  loginButton.querySelector("span:last-child").textContent = isBusy
    ? "等待浏览器回跳"
    : "打开统一认证登录";
}

function renderResult(result) {
  resultBadge.textContent = "已生成";
  resultBadge.classList.remove("muted");
  callbackState.textContent = "已接收";
  lastServers = result.servers;

  if (result.servers.length === 0) {
    serverList.className = "server-list empty-state";
    serverList.textContent = "controller 未返回可用 SDWAN 节点。";
    renderProxyStatus(proxyStatus);
    return;
  }

  serverList.className = "server-list";
  serverList.replaceChildren(
    ...result.servers.map((server) => {
      const item = document.createElement("article");
      item.className = "server-item";
      item.innerHTML = `
        <div>
          <strong>${server.name}</strong>
          <span>${server.host}:${server.port}</span>
        </div>
        <button class="server-action" data-server-id="${server.id}" type="button">
          ${proxyStatus.running && proxyStatus.serverId === server.id ? "已连接" : "连接"}
        </button>
      `;
      return item;
    }),
  );
  renderProxyStatus(proxyStatus);
}

function renderProxyStatus(status) {
  proxyStatus = status;
  proxyState.textContent = status.running
    ? `${status.serverName} / ${status.tunName}`
    : "未连接";
  stopProxyButton.disabled = !status.running;

  const notice = status.lastError
    ? `error:${status.lastError}`
    : status.lastMessage
      ? `log:${status.lastMessage}`
      : "";
  if (notice && notice !== lastProxyNotice) {
    lastProxyNotice = notice;
    appendLog(status.lastError ? "错误" : "代理", status.lastError ?? status.lastMessage, status.lastError ? "error" : "info");
  }

  for (const button of serverList.querySelectorAll(".server-action")) {
    const serverId = Number(button.dataset.serverId);
    const isActive = status.running && status.serverId === serverId;
    button.textContent = isActive ? "已连接" : "连接";
    button.disabled = isActive;
  }
}

function startProxyPolling() {
  window.setInterval(async () => {
    try {
      renderProxyStatus(await invoke("get_proxy_status"));
    } catch {
      renderProxyStatus({
        running: false,
        serverId: null,
        serverName: null,
        tunName: "iwan0",
        lastMessage: null,
        lastError: null,
      });
    }
  }, 1500);
}

async function bindEvents() {
  await listen("iwan-status", (event) => {
    const payload = event.payload;
    stageBadge.textContent = payload.stage;
    appendLog(payload.stage, payload.message);
  });

  await listen("iwan-result", (event) => {
    setBusy(false);
    renderResult(event.payload);
    appendLog("完成", "SDWAN 节点已准备。", "success");
  });

  await listen("iwan-proxy-status", (event) => {
    renderProxyStatus(event.payload);
  });

  await listen("iwan-proxy-log", (event) => {
    const payload = event.payload;
    appendLog(payload.stage, payload.message);
  });

  await listen("iwan-error", (event) => {
    setBusy(false);
    stageBadge.textContent = "失败";
    appendLog("错误", event.payload.message, "error");
  });
}

async function checkRequirements() {
  const items = await invoke("check_requirements");
  const failed = items.filter((item) => !item.ok);
  if (failed.length === 0) {
    appendLog("检查", "代理运行环境检查通过。", "success");
    return;
  }
  for (const item of failed) {
    appendLog(item.name, item.message, "error");
  }
}

loginButton.addEventListener("click", async () => {
  setBusy(true);
  callbackState.textContent = "等待浏览器跳转";
  try {
    const started = await invoke("start_login");
    deviceUuid.textContent = started.deviceUuid;
    appendLog("浏览器", "已打开 USTC 统一认证页面。");
  } catch (error) {
    setBusy(false);
    appendLog("错误", String(error), "error");
  }
});

serverList.addEventListener("click", async (event) => {
  const button = event.target.closest(".server-action");
  if (!button) return;
  const serverId = Number(button.dataset.serverId);
  button.disabled = true;
  button.textContent = "连接中";
  try {
    const status = await invoke("start_proxy", { serverId });
    renderProxyStatus(status);
    const server = lastServers.find((item) => item.id === serverId);
    appendLog("代理", `${server?.name ?? "SDWAN 节点"} 已选择。`);
  } catch (error) {
    appendLog("错误", String(error), "error");
    renderProxyStatus(proxyStatus);
  }
});

stopProxyButton.addEventListener("click", async () => {
  stopProxyButton.disabled = true;
  try {
    const status = await invoke("stop_proxy");
    renderProxyStatus(status);
  } catch (error) {
    appendLog("错误", String(error), "error");
  }
});

clearLogButton.addEventListener("click", () => {
  logList.replaceChildren();
});

bindEvents()
  .then(async () => {
    await checkRequirements();
    const result = await invoke("get_last_result");
    if (result) renderResult(result);
    renderProxyStatus(await invoke("get_proxy_status"));
    startProxyPolling();
  })
  .catch((error) => appendLog("初始化", String(error), "error"));
