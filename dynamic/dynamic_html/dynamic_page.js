const EMBEDDED = Boolean(window.DSP_DYNAMIC_EMBEDDED);
const CONFIG = window.DSP_DYNAMIC_CONFIG || {};
const SUPABASE_URL = CONFIG.supabaseUrl || "";
const SUPABASE_KEY = CONFIG.supabaseAnonKey || "";
const API_BASE = (CONFIG.apiBase || "http://localhost:8000/dynamic-api").replace(/\/$/, "");
const WS_ALERT = API_BASE.replace(/^http/i, (match) => (match.toLowerCase() === "https" ? "wss" : "ws")) + "/ws";
const WS_TERM = API_BASE.replace(/^http/i, (match) => (match.toLowerCase() === "https" ? "wss" : "ws")) + "/ws/terminal";
const VM_HOST = CONFIG.vmHost || "192.168.25.132";
const VM_USER = CONFIG.vmUser || "pro";
const VM_PORT = CONFIG.vmPort || "22";

const hasSupabaseConfig = Boolean(SUPABASE_URL && SUPABASE_KEY && window.supabase);
const sbClient = hasSupabaseConfig ? window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY) : null;

let currentUser = null;
let isSignUp = false;
let selectedFile = null;
let initialized = false;
let term = null;
let fitAddon = null;
let termWs = null;
let alertWs = null;
let alertPing = null;
let alertReconnectTimer = null;
let logCount = 0;
const counters = { HIGH: 0, MEDIUM: 0, LOW: 0 };

function byId(id) {
  return document.getElementById(id);
}

function setLoginError(message, ok = false) {
  const node = byId("login-err");
  if (!node) return;
  node.style.color = ok ? "var(--accent)" : "var(--high)";
  node.textContent = message;
}

function setMutedState(id, message) {
  const node = byId(id);
  if (!node) return;
  node.innerHTML = `<div class="muted-state">${message}</div>`;
}

function safeWrite(text) {
  if (!term) return;
  term.write(text);
}


async function bootstrap() {
  wireUploadUi();

  if (!hasSupabaseConfig) {
    if (EMBEDDED) {
      setMutedState("notebook-list", "Supabase 설정을 찾지 못했습니다. login/config.js 값을 확인하세요.");
      setMutedState("container-list", "동적 분석 기능을 초기화할 수 없습니다.");
    } else {
      setLoginError("Supabase 설정을 찾지 못했습니다. login/config.js 값을 확인하세요.");
    }
    return;
  }

  sbClient.auth.onAuthStateChange((_event, session) => {
    if (session?.user) {
      currentUser = session.user;
      onLogin();
      return;
    }
    currentUser = null;
    initialized = false;
    if (termWs) termWs.close();
    if (alertWs) alertWs.close();
    if (alertReconnectTimer) clearTimeout(alertReconnectTimer);
    if (!EMBEDDED) {
      const loginScreen = byId("login-screen");
      if (loginScreen) loginScreen.style.display = "flex";
    }
  });

  try {
    const { data } = await sbClient.auth.getSession();
    if (data?.session?.user) {
      currentUser = data.session.user;
      onLogin();
    } else if (EMBEDDED) {
      setMutedState("notebook-list", "DSP 로그인 세션을 찾지 못했습니다. 대시보드 로그인 후 다시 열어주세요.");
      setMutedState("container-list", "세션이 없어서 동적 분석 화면을 시작하지 못했습니다.");
    }
  } catch (error) {
    console.error(error);
    if (!EMBEDDED) {
      setLoginError("세션 확인 중 오류가 발생했습니다.");
    }
  }
}

function wireUploadUi() {
  const dropZone = byId("drop-zone");
  const fileInput = byId("file-input");
  const modalMemo = byId("modal-memo");
  const loginPassword = byId("login-pw");
  const modal = byId("add-modal");

  if (dropZone && fileInput) {
    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", (event) => {
      event.preventDefault();
      dropZone.classList.add("dragover");
    });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragover"));
    dropZone.addEventListener("drop", (event) => {
      event.preventDefault();
      dropZone.classList.remove("dragover");
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      if (!file.name.toLowerCase().endsWith(".tar")) {
        showSystemToast(".tar 파일만 업로드할 수 있습니다.", true);
        return;
      }
      showFileInfo(file);
    });
    fileInput.addEventListener("change", () => {
      const file = fileInput.files?.[0];
      if (file) {
        showFileInfo(file);
      }
    });
  }

  if (modalMemo) {
    modalMemo.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        saveToNotebook();
      }
    });
  }

  if (loginPassword) {
    loginPassword.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        handleAuth();
      }
    });
  }

  if (modal) {
    modal.addEventListener("click", (event) => {
      if (event.target === modal) {
        closeModal();
      }
    });
  }
}

function onLogin() {
  if (!currentUser) return;

  const loginScreen = byId("login-screen");
  if (loginScreen) {
    loginScreen.style.display = "none";
  }

  const emailDisplay = byId("user-email-display");
  if (emailDisplay) {
    emailDisplay.textContent = currentUser.email || "";
  }

  if (initialized) {
    loadNotebook();
    loadContainers();
    return;
  }

  initialized = true;
  if (term) {
    reconnectTerminal();
  } else {
    initTerminal();
  }
  connectAlertWS();
  loadNotebook();
  loadContainers();
}

async function handleAuth() {
  if (!sbClient) return;

  const email = byId("login-email")?.value.trim() || "";
  const password = byId("login-pw")?.value || "";
  const button = byId("login-btn");

  if (!email || !password) {
    setLoginError("이메일과 비밀번호를 입력하세요.");
    return;
  }

  if (button) {
    button.disabled = true;
    button.textContent = isSignUp ? "회원가입 중..." : "로그인 중...";
  }
  setLoginError("");

  try {
    const result = isSignUp
      ? await sbClient.auth.signUp({ email, password })
      : await sbClient.auth.signInWithPassword({ email, password });

    if (result.error) {
      setLoginError(result.error.message);
      return;
    }

    if (isSignUp && !result.data.session) {
      setLoginError("회원가입이 완료되었습니다. 이메일 인증 후 로그인하세요.", true);
      return;
    }

    currentUser = result.data.user || result.data.session?.user || null;
    onLogin();
  } catch (error) {
    setLoginError(error.message || "로그인 처리 중 오류가 발생했습니다.");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = isSignUp ? "회원가입" : "로그인";
    }
  }
}

function toggleAuthMode() {
  isSignUp = !isSignUp;
  const toggleButton = byId("login-toggle");
  const submitButton = byId("login-btn");
  const subtitle = byId("login-subtitle");

  if (toggleButton) {
    toggleButton.textContent = isSignUp
      ? "이미 계정이 있으면 로그인으로 전환"
      : "계정이 없으면 회원가입으로 전환";
  }
  if (submitButton) {
    submitButton.textContent = isSignUp ? "회원가입" : "로그인";
  }
  if (subtitle) {
    subtitle.textContent = isSignUp
      ? "DSP와 동일한 Supabase 프로젝트에 사용자 계정을 만듭니다."
      : "현재 DSP 계정으로 로그인하면 동적 분석 환경이 바로 연결됩니다.";
  }
  setLoginError("");
}

async function handleLogout() {
  if (!sbClient) return;
  await sbClient.auth.signOut();
  if (EMBEDDED && window.top) {
    window.top.location.href = "/login/";
    return;
  }
  window.location.reload();
}

function openModal() {
  const modal = byId("add-modal");
  if (modal) modal.classList.add("show");
}

function closeModal() {
  const modal = byId("add-modal");
  if (modal) modal.classList.remove("show");
  clearFile();
  const memo = byId("modal-memo");
  if (memo) memo.value = "";
  const progress = byId("upload-progress");
  if (progress) progress.style.display = "none";
  const bar = byId("upload-progress-bar");
  if (bar) bar.style.width = "0%";
  const saveButton = byId("save-btn");
  if (saveButton) {
    saveButton.textContent = "저장하고 업로드";
    saveButton.disabled = false;
  }
}

function showFileInfo(file) {
  selectedFile = file;
  const dropZone = byId("drop-zone");
  const fileInfo = byId("file-info");
  const name = byId("file-info-name");
  const size = byId("file-info-size");
  const input = byId("file-input");

  if (dropZone) dropZone.style.display = "none";
  if (fileInfo) fileInfo.style.display = "flex";
  if (name) name.textContent = file.name;
  if (size) size.textContent = `${(file.size / (1024 * 1024)).toFixed(1)} MB`;
  if (input && input.files?.[0] !== file) {
    input.value = "";
  }
}

function clearFile() {
  selectedFile = null;
  const dropZone = byId("drop-zone");
  const fileInfo = byId("file-info");
  const input = byId("file-input");

  if (dropZone) dropZone.style.display = "block";
  if (fileInfo) fileInfo.style.display = "none";
  if (input) input.value = "";
}

async function saveToNotebook() {
  if (!selectedFile) {
    showSystemToast("업로드할 tar 파일을 먼저 선택하세요.", true);
    return;
  }
  if (!currentUser || !sbClient) return;

  const memo = byId("modal-memo")?.value.trim() || "";
  const saveButton = byId("save-btn");
  const progress = byId("upload-progress");
  const bar = byId("upload-progress-bar");

  if (saveButton) {
    saveButton.disabled = true;
    saveButton.textContent = "업로드 중...";
  }
  if (progress) progress.style.display = "block";
  if (bar) bar.style.width = "0%";

  const formData = new FormData();
  formData.append("file", selectedFile);
  formData.append("memo", memo);

  const xhr = new XMLHttpRequest();
  xhr.upload.addEventListener("progress", (event) => {
    if (!event.lengthComputable || !bar) return;
    bar.style.width = `${(event.loaded / event.total) * 100}%`;
  });

  xhr.onload = async () => {
    try {
      const response = JSON.parse(xhr.responseText || "{}");
      if (!response.ok) {
        showSystemToast(response.message || "업로드에 실패했습니다.", true);
        return;
      }

      const { error } = await sbClient.from("user_images").insert({
        user_id: currentUser.id,
        image_name: response.image_name,
        memo: memo || null,
      });

      if (error) {
        showSystemToast(error.message || "이미지 메모 저장에 실패했습니다.", true);
        return;
      }

      closeModal();
      loadNotebook();
      showSystemToast(`${response.image_name} 이미지를 등록했습니다.`);
    } catch (error) {
      showSystemToast(error.message || "업로드 응답 처리 중 오류가 발생했습니다.", true);
    } finally {
      if (saveButton) {
        saveButton.disabled = false;
        saveButton.textContent = "저장하고 업로드";
      }
    }
  };

  xhr.onerror = () => {
    showSystemToast("동적 분석 API 서버와 연결하지 못했습니다.", true);
    if (saveButton) {
      saveButton.disabled = false;
      saveButton.textContent = "저장하고 업로드";
    }
  };

  xhr.open("POST", `${API_BASE}/images/upload`);
  xhr.send(formData);
}

async function loadNotebook() {
  if (!currentUser || !sbClient) return;

  const list = byId("notebook-list");
  if (!list) return;

  const { data, error } = await sbClient
    .from("user_images")
    .select("*")
    .eq("user_id", currentUser.id)
    .order("created_at", { ascending: false });

  if (error || !data?.length) {
    setMutedState("notebook-list", error ? "이미지 목록을 불러오지 못했습니다." : "등록된 이미지가 없습니다.");
    return;
  }

  list.innerHTML = "";
  data.forEach((item) => {
    const card = document.createElement("div");
    card.className = "notebook-item";
    card.innerHTML = `
      <div class="notebook-img-name">${escapeHtml(item.image_name)}</div>
      ${item.memo ? `<div class="notebook-memo">${escapeHtml(item.memo)}</div>` : ""}
      <div class="notebook-actions">
        <button class="accent-btn small-btn" type="button" onclick="runFromNotebook('${escapeJs(item.image_name)}')">실행</button>
        <button class="ghost-btn small-btn" type="button" onclick="deleteFromNotebook('${escapeJs(item.id)}')">삭제</button>
      </div>
    `;
    list.appendChild(card);
  });
}

async function deleteFromNotebook(id) {
  if (!sbClient || !window.confirm("이 이미지를 목록에서 삭제할까요?")) {
    return;
  }
  const { error } = await sbClient.from("user_images").delete().eq("id", id);
  if (error) {
    showSystemToast(error.message || "삭제에 실패했습니다.", true);
    return;
  }
  loadNotebook();
}

async function runFromNotebook(imageName) {
  safeWrite(`\r\n[run] ${imageName}\r\n`);
  try {
    const response = await fetch(`${API_BASE}/containers/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ image: imageName, name: "" }),
    });
    const data = await response.json();
    safeWrite(`${data.ok ? "[ok]" : "[error]"} ${data.message}\r\n`);
    if (data.ok) {
      setTimeout(loadContainers, 800);
    }
  } catch (error) {
    safeWrite(`[error] ${error.message}\r\n`);
  }
}

function initTerminal() {
  if (term) return;

  term = new window.Terminal({
    cursorBlink: true,
    fontSize: 13,
    fontFamily: "'IBM Plex Mono', monospace",
    scrollback: 1200,
    theme: {
      background: "#081321",
      foreground: "#ccd6f6",
      cursor: "#64ffda",
      black: "#081321",
      red: "#ff6b6b",
      green: "#64ffda",
      yellow: "#ffb84d",
      blue: "#4dd0e1",
      magenta: "#a78bfa",
      cyan: "#96fff0",
      white: "#ccd6f6",
      brightBlack: "#415a77",
      brightGreen: "#98ffec",
    },
  });

  fitAddon = new window.FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(byId("terminal-container"));
  fitAddon.fit();
  term.focus();
  window.addEventListener("resize", () => fitAddon.fit());
  byId("terminal-container")?.addEventListener("click", () => term.focus());

  term.onData((data) => {
    if (termWs?.readyState === WebSocket.OPEN) {
      termWs.send(data);
    }
  });

  term.onResize(({ rows, cols }) => {
    if (termWs?.readyState === WebSocket.OPEN) {
      termWs.send(JSON.stringify({ type: "resize", rows, cols }));
    }
  });

  connectTerminal();
}

function connectTerminal() {
  if (!term) return;
  if (termWs) termWs.close();

  termWs = new WebSocket(WS_TERM);
  termWs.binaryType = "arraybuffer";

  termWs.onopen = () => {
    setConnectionState("term-dot", "term-label", true, "terminal connected");
    term.focus();
  };

  termWs.onmessage = (event) => {
    if (typeof event.data === "string") {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "auth_required") {
          return;
        }
      } catch (_error) {
        term.write(String(event.data));
        return;
      }
    }
    if (event.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(event.data));
      return;
    }
    term.write(String(event.data));
  };

  termWs.onclose = () => {
    setConnectionState("term-dot", "term-label", false, "terminal disconnected");
    safeWrite("\r\n[terminal disconnected]\r\n");
  };
}

function reconnectTerminal() {
  if (!term) return;
  term.clear();
  connectTerminal();
}

function connectAlertWS() {
  if (alertWs) alertWs.close();

  alertWs = new WebSocket(WS_ALERT);
  alertWs.onopen = () => {
    setConnectionState("alert-dot", "alert-label", true, "alerts connected");
    if (alertPing) clearInterval(alertPing);
    if (alertReconnectTimer) clearTimeout(alertReconnectTimer);
    alertPing = setInterval(() => {
      if (alertWs?.readyState === WebSocket.OPEN) {
        alertWs.send("ping");
      }
    }, 30000);
  };

  alertWs.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type !== "alert") return;
    addLog(data);
    showToast(data);
    setTimeout(loadContainers, 800);
  };

  alertWs.onclose = () => {
    setConnectionState("alert-dot", "alert-label", false, "alerts reconnecting");
    if (alertPing) clearInterval(alertPing);
    if (!currentUser) return;
    alertReconnectTimer = setTimeout(connectAlertWS, 2000);
  };
}

function setConnectionState(dotId, labelId, connected, label) {
  const dot = byId(dotId);
  const labelNode = byId(labelId);
  if (dot) {
    dot.className = connected ? "ws-dot connected" : "ws-dot error";
  }
  if (labelNode) {
    labelNode.textContent = label;
  }
}

async function loadContainers() {
  try {
    const response = await fetch(`${API_BASE}/containers`);
    const data = await response.json();
    renderContainers(data.containers || []);
  } catch (error) {
    setMutedState("container-list", "컨테이너 목록을 불러오지 못했습니다.");
  }
}

function renderContainers(containers) {
  const list = byId("container-list");
  if (!list) return;

  if (!containers.length) {
    list.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">[]</div>
        <p>표시할 컨테이너가 없습니다.</p>
      </div>
    `;
    return;
  }

  list.innerHTML = "";
  containers.forEach((container) => {
    const statusClass = container.status === "running" ? "running" : (container.status === "exited" ? "exited" : "created");
    const runningActions = `
      <button class="ghost-btn small-btn" type="button" onclick="containerAction('${escapeJs(container.name)}', 'stop')">중지</button>
      <button class="ghost-btn small-btn" type="button" onclick="containerAction('${escapeJs(container.name)}', 'restart')">재시작</button>
    `;
    const idleAction = `
      <button class="accent-btn small-btn" type="button" onclick="containerAction('${escapeJs(container.name)}', 'start')">시작</button>
    `;

    const card = document.createElement("div");
    card.className = "container-card";
    card.innerHTML = `
      <div class="card-top">
        <span class="status-dot ${statusClass}"></span>
        <span class="card-name">${escapeHtml(container.name)}</span>
        <span class="card-image">${escapeHtml(container.image || "")}</span>
      </div>
      <div class="card-actions">
        ${container.status === "running" ? runningActions : idleAction}
        <button class="ghost-btn small-btn" type="button" onclick="containerAction('${escapeJs(container.name)}', 'remove')">삭제</button>
      </div>
    `;
    list.appendChild(card);
  });
}

async function containerAction(name, action) {
  safeWrite(`\r\n[docker ${action}] ${name}\r\n`);
  try {
    const response = await fetch(`${API_BASE}/containers/action`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, action }),
    });
    const data = await response.json();
    safeWrite(`${data.ok ? "[ok]" : "[error]"} ${data.message}\r\n`);
    if (data.ok) {
      setTimeout(loadContainers, 800);
    }
  } catch (error) {
    safeWrite(`[error] ${error.message}\r\n`);
  }
}

function addLog(data) {
  const emptyState = byId("empty-state");
  if (emptyState) {
    emptyState.style.display = "none";
  }

  logCount += 1;
  counters[data.analysis.risk] = (counters[data.analysis.risk] || 0) + 1;

  byId("cnt-high").textContent = String(counters.HIGH);
  byId("cnt-med").textContent = String(counters.MEDIUM);
  byId("cnt-low").textContent = String(counters.LOW);
  byId("log-count").textContent = `${logCount} events`;

  const item = document.createElement("div");
  item.className = `log-item ${data.analysis.risk}`;

  const timestamp = new Date(data.timestamp).toLocaleTimeString("ko-KR");
  item.innerHTML = `
    <div class="log-top">
      <span class="risk-badge ${data.analysis.risk}">${data.analysis.risk}</span>
      <span class="log-rule">${escapeHtml(data.analysis.rule)}</span>
      <span class="log-time">${timestamp}</span>
    </div>
    <div class="log-detail">${escapeHtml(data.analysis.detail)}</div>
  `;

  const logList = byId("log-list");
  logList.insertBefore(item, logList.firstChild);
}

function clearLogs() {
  logCount = 0;
  counters.HIGH = 0;
  counters.MEDIUM = 0;
  counters.LOW = 0;
  byId("cnt-high").textContent = "0";
  byId("cnt-med").textContent = "0";
  byId("cnt-low").textContent = "0";
  byId("log-count").textContent = "0 events";

  const logList = byId("log-list");
  logList.innerHTML = `
    <div class="empty-state" id="empty-state">
      <div class="empty-icon">!</div>
      <p>아직 감지된 이벤트가 없습니다.</p>
      <span>컨테이너 실행이나 docker exec 동작을 기다리는 중입니다.</span>
    </div>
  `;
}

function showToast(data) {
  const risk = data.analysis.risk;
  const title = `${risk} - ${data.container}`;
  createToast(title, data.analysis.rule, risk, risk === "HIGH" ? 5000 : 3200);
}

function showSystemToast(message, isError = false) {
  createToast(isError ? "오류" : "안내", message, isError ? "HIGH" : "LOW", 3200);
}

function createToast(title, message, level, timeout) {
  const container = byId("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast ${level}`;
  toast.innerHTML = `
    <div class="toast-title">${escapeHtml(title)}</div>
    <div class="toast-msg">${escapeHtml(message)}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-4px)";
    toast.style.transition = "opacity 0.2s ease, transform 0.2s ease";
    setTimeout(() => toast.remove(), 220);
  }, timeout);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeJs(value) {
  return String(value ?? "").replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}

document.addEventListener("DOMContentLoaded", bootstrap);
