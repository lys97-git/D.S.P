import asyncio
import json
import os
import subprocess
import tempfile
import threading
import uuid
import shlex
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, FastAPI, File, Form, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import paramiko

try:
    import docker
except ImportError:
    docker = None


SUSPICIOUS_COMMANDS = ["curl", "wget", "bash", "sh", "nc", "ncat", "python", "perl", "chmod", "chown"]
SUSPICIOUS_LOG_WORDS = ["error", "denied", "failed", "unauthorized", "forbidden", "critical", "exploit"]
RESTART_THRESHOLD = 3

router = APIRouter(prefix="/dynamic-api", tags=["dynamic-analysis"])


class RunRequest(BaseModel):
    image: str
    name: str = ""


class ActionRequest(BaseModel):
    name: str
    action: str


class ExecRequest(BaseModel):
    name: str
    command: str


class DynamicBackendState:
    def __init__(self):
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.docker_client = None
        self.listener_started = False
        self.listener_lock = threading.Lock()
        self.alert_clients: list[WebSocket] = []
        self.restart_counter = defaultdict(int)
        self.log_watchers = set()
        self.upload_dir = Path(os.environ.get("DYNAMIC_UPLOAD_DIR", Path(tempfile.gettempdir()) / "dsp_dynamic_uploads"))
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def ensure_docker_client(self):
        if self.docker_client is not None:
            return self.docker_client
        if docker is None:
            return None
        try:
            client = docker.from_env()
            client.ping()
            self.docker_client = client
        except Exception as exc:
            print(f"[dynamic] Docker connection failed: {exc}")
            self.docker_client = None
        return self.docker_client

    def ensure_background_threads(self):
        client = self.ensure_docker_client()
        if client is None or self.loop is None:
            return
        with self.listener_lock:
            if self.listener_started:
                return
            threading.Thread(target=self._docker_event_listener, daemon=True).start()
            for container in client.containers.list(all=True):
                self.ensure_log_watch(container.name)
            self.listener_started = True
            print("[dynamic] Background listeners started.")

    def ensure_log_watch(self, container_name: str):
        if not container_name or container_name in self.log_watchers:
            return
        self.log_watchers.add(container_name)
        threading.Thread(target=self._watch_logs, args=(container_name,), daemon=True).start()

    def schedule_alert(self, event_type: str, container: str, extra: Optional[dict] = None):
        if self.loop is None:
            return
        future = asyncio.run_coroutine_threadsafe(
            _send_alert(event_type, container, extra or {}),
            self.loop,
        )
        try:
            future.result(timeout=0)
        except Exception:
            pass

    def _docker_event_listener(self):
        client = self.ensure_docker_client()
        if client is None:
            return
        print("[dynamic] Docker event listener started.")
        try:
            for event in client.events(decode=True):
                action_raw = event.get("Action", "")
                actor = event.get("Actor", {})
                attrs = actor.get("Attributes", {})
                container = attrs.get("name") or actor.get("ID", "unknown")[:12]
                extra = {}

                if action_raw.startswith("exec_start"):
                    action = "exec_start"
                    extra["command"] = action_raw.replace("exec_start:", "").strip()
                elif action_raw == "die":
                    action = "die"
                    extra["exit_code"] = attrs.get("exitCode", "0")
                elif action_raw == "start":
                    action = "start"
                    self.ensure_log_watch(container)
                elif action_raw == "restart":
                    action = "restart"
                    self.ensure_log_watch(container)
                else:
                    action = action_raw

                if action in {"start", "exec_start", "die", "restart"}:
                    self.schedule_alert(action, container, extra)
        except Exception as exc:
            print(f"[dynamic] Docker event listener stopped: {exc}")

    def _watch_logs(self, container_name: str):
        client = self.ensure_docker_client()
        if client is None:
            return
        try:
            container = client.containers.get(container_name)
            for line in container.logs(stream=True, follow=True, tail=0):
                log_line = line.decode("utf-8", errors="replace").strip()
                if any(keyword in log_line.lower() for keyword in SUSPICIOUS_LOG_WORDS):
                    self.schedule_alert("log_alert", container_name, {"log_line": log_line})
        except Exception as exc:
            print(f"[dynamic] Log watch ended for {container_name}: {exc}")
        finally:
            self.log_watchers.discard(container_name)


STATE = DynamicBackendState()


def _analyze_event(event_type: str, container: str, extra: dict):
    if event_type == "exec_start":
        command = extra.get("command", "").lower()
        matched = [cmd for cmd in SUSPICIOUS_COMMANDS if cmd in command]
        if matched:
            return {
                "risk": "HIGH",
                "rule": f"Suspicious command detected: {', '.join(matched)}",
                "detail": f"[{container}] {command or '(empty command)'}",
            }
        return {
            "risk": "MEDIUM",
            "rule": "docker exec activity detected",
            "detail": f"[{container}] {command or '(empty command)'}",
        }
    if event_type == "restart":
        STATE.restart_counter[container] += 1
        count = STATE.restart_counter[container]
        if count >= RESTART_THRESHOLD:
            return {
                "risk": "HIGH",
                "rule": f"Repeated restart detected ({count})",
                "detail": f"[{container}] restarted {count} times",
            }
        return {
            "risk": "MEDIUM",
            "rule": f"Restart detected ({count}/{RESTART_THRESHOLD})",
            "detail": f"[{container}] restart event",
        }
    if event_type == "die":
        exit_code = str(extra.get("exit_code", "0"))
        if exit_code != "0":
            return {
                "risk": "MEDIUM",
                "rule": f"Container exited abnormally (code {exit_code})",
                "detail": f"[{container}] abnormal exit",
            }
        return {
            "risk": "LOW",
            "rule": "Container exited normally",
            "detail": f"[{container}] normal exit",
        }
    if event_type == "log_alert":
        log_line = extra.get("log_line", "")
        matched = [keyword for keyword in SUSPICIOUS_LOG_WORDS if keyword in log_line.lower()]
        return {
            "risk": "MEDIUM",
            "rule": f"Suspicious log detected: {', '.join(matched)}",
            "detail": f"[{container}] {log_line[:160]}",
        }
    return {
        "risk": "LOW",
        "rule": f"Container event: {event_type}",
        "detail": f"[{container}] {event_type}",
    }


async def _broadcast(payload: dict):
    dead_clients = []
    for client in list(STATE.alert_clients):
        try:
            await client.send_json(payload)
        except Exception:
            dead_clients.append(client)
    for client in dead_clients:
        if client in STATE.alert_clients:
            STATE.alert_clients.remove(client)


async def _send_alert(event_type: str, container: str, extra: dict):
    analysis = _analyze_event(event_type, container, extra)
    payload = {
        "type": "alert",
        "event_type": event_type,
        "container": container,
        "extra": extra,
        "analysis": analysis,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await _broadcast(payload)
    print(f"[dynamic][{analysis['risk']}] {analysis['rule']} | {container}")


def _docker_unavailable_response():
    return {"ok": False, "message": "Docker is not connected on this host."}


def _remote_bash_command(command: str):
    escaped = command.replace("'", r"'\''")
    return f"bash -lc '{escaped}'"


def _vm_terminal_config():
    vm_host = os.environ.get("DYNAMIC_VM_HOST", "192.168.25.132").strip()
    vm_user = os.environ.get("DYNAMIC_VM_USER", "pro").strip()
    vm_port = int((os.environ.get("DYNAMIC_VM_PORT", "22") or "22").strip())
    vm_init_command = os.environ.get("DYNAMIC_VM_INIT_COMMAND", "").strip()
    return {
        "enabled": bool(vm_host and vm_user),
        "host": vm_host,
        "user": vm_user,
        "port": vm_port,
        "init_command": vm_init_command,
    }


def _local_terminal_command():
    if os.name == "nt":
        command = [os.environ.get("COMSPEC", "cmd.exe"), "/Q", "/K"]
    else:
        command = [os.environ.get("SHELL", "/bin/bash"), "-i"]
    banner = f"[DSP Dynamic Terminal] Connected to local shell: {' '.join(shlex.quote(part) for part in command)}\r\n"
    return command, banner


def attach_dynamic_backend(app: FastAPI):
    if getattr(app.state, "dynamic_backend_attached", False):
        return

    @app.on_event("startup")
    async def _dynamic_backend_startup():
        STATE.loop = asyncio.get_running_loop()
        STATE.ensure_background_threads()

    app.include_router(router)
    app.state.dynamic_backend_attached = True


async def _receive_terminal_auth(websocket: WebSocket, prompt: str):
    password = ""
    cols = 120
    rows = 32
    await websocket.send_bytes(prompt.encode("utf-8", errors="replace"))

    while True:
        try:
            message = await asyncio.wait_for(websocket.receive(), timeout=120)
        except asyncio.TimeoutError as exc:
            raise RuntimeError("SSH authentication timed out before the password was entered.") from exc

        if message.get("type") == "websocket.disconnect":
            raise WebSocketDisconnect()

        raw_bytes = message.get("bytes")
        text = message.get("text")
        chunk = ""

        if raw_bytes is not None:
            chunk = raw_bytes.decode("utf-8", errors="ignore")
        elif text is not None:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                chunk = text
            else:
                if not isinstance(payload, dict):
                    chunk = text
                    payload = None
                if payload is None:
                    pass
                elif payload.get("type") == "resize":
                    cols = int(payload.get("cols", cols))
                    rows = int(payload.get("rows", rows))
                    continue
                elif payload.get("type") == "auth":
                    password = str(payload.get("password", ""))
                    if password:
                        await websocket.send_bytes(b"\r\n")
                        return password, cols, rows
                    continue
                else:
                    continue

        for char in chunk:
            if char in ("\r", "\n"):
                await websocket.send_bytes(b"\r\n")
                if password:
                    return password, cols, rows
                await websocket.send_bytes(
                    b"[DSP Dynamic Terminal] Empty password. Try again.\r\n"
                )
                await websocket.send_bytes(prompt.encode("utf-8", errors="replace"))
                break

            if char in ("\x08", "\x7f"):
                if password:
                    password = password[:-1]
                    await websocket.send_bytes(b"\b \b")
                continue

            if char == "\x03":
                raise RuntimeError("SSH authentication cancelled.")

            if char.isprintable():
                password += char
                await websocket.send_bytes(b"*")


def _connect_vm_shell(password: str, cols: int = 120, rows: int = 32):
    config = _vm_terminal_config()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=config["host"],
        port=config["port"],
        username=config["user"],
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        banner_timeout=15,
        auth_timeout=15,
    )
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(30)

    channel = client.invoke_shell(term="xterm", width=cols, height=rows)
    banner = (
        f"[DSP Dynamic Terminal] Connected to Ubuntu VM {config['user']}@{config['host']}:{config['port']}\r\n"
    )
    if config["init_command"]:
        channel.send(config["init_command"] + "\n")
        banner += f"[DSP Dynamic Terminal] Remote bootstrap: {config['init_command']}\r\n"
    return client, channel, banner


@router.websocket("/ws")
async def alert_ws(websocket: WebSocket):
    await websocket.accept()
    STATE.alert_clients.append(websocket)
    await websocket.send_json(
        {
            "type": "connected",
            "message": "Dynamic alert stream connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in STATE.alert_clients:
            STATE.alert_clients.remove(websocket)


@router.websocket("/ws/terminal")
async def terminal_ws(websocket: WebSocket):
    await websocket.accept()
    vm_config = _vm_terminal_config()

    if vm_config["enabled"]:
        ssh_client = None
        ssh_channel = None

        try:
            prompt = (
                f"[DSP Dynamic Terminal] SSH login required.\r\n"
                f"{vm_config['user']}@{vm_config['host']}'s password: "
            )
            password, cols, rows = await _receive_terminal_auth(websocket, prompt)
            ssh_client, ssh_channel, banner_text = await asyncio.to_thread(
                _connect_vm_shell,
                password,
                cols,
                rows,
            )
            await websocket.send_bytes(banner_text.encode("utf-8", errors="replace"))

            async def _ssh_to_ws():
                while True:
                    if ssh_channel.closed:
                        break
                    if ssh_channel.recv_ready():
                        chunk = await asyncio.to_thread(ssh_channel.recv, 4096)
                        if not chunk:
                            break
                        await websocket.send_bytes(chunk)
                        continue
                    await asyncio.sleep(0.05)

            async def _ws_to_ssh():
                while True:
                    message = await websocket.receive()
                    if message.get("type") == "websocket.disconnect":
                        break

                    raw_bytes = message.get("bytes")
                    if raw_bytes is None:
                        text = message.get("text", "")
                        try:
                            payload = json.loads(text)
                            if isinstance(payload, dict) and payload.get("type") == "resize":
                                cols = int(payload.get("cols", 120))
                                rows = int(payload.get("rows", 32))
                                await asyncio.to_thread(ssh_channel.resize_pty, width=cols, height=rows)
                                continue
                            raw_bytes = text.encode("utf-8", errors="ignore")
                        except json.JSONDecodeError:
                            raw_bytes = text.encode("utf-8", errors="ignore")

                    if raw_bytes:
                        await asyncio.to_thread(ssh_channel.send, raw_bytes.decode("utf-8", errors="ignore"))

            await asyncio.gather(_ssh_to_ws(), _ws_to_ssh())
        except WebSocketDisconnect:
            pass
        except paramiko.AuthenticationException:
            await websocket.send_bytes(b"[DSP Dynamic Terminal] SSH authentication failed.\r\n")
        except Exception as exc:
            await websocket.send_bytes(f"[DSP Dynamic Terminal] {exc}\r\n".encode("utf-8", errors="replace"))
        finally:
            try:
                if ssh_channel is not None:
                    ssh_channel.close()
            except Exception:
                pass
            try:
                if ssh_client is not None:
                    ssh_client.close()
            except Exception:
                pass
            await websocket.close()
        return

    command, banner_text = _local_terminal_command()
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        creationflags=creationflags,
    )
    banner = banner_text.encode("utf-8", errors="replace")
    await websocket.send_bytes(banner)

    async def _stdout_to_ws():
        while True:
            chunk = await process.stdout.read(1024)
            if not chunk:
                break
            await websocket.send_bytes(chunk)

    async def _ws_to_stdin():
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect":
                break

            raw_bytes = message.get("bytes")
            if raw_bytes is None:
                text = message.get("text", "")
                try:
                    payload = json.loads(text)
                    if isinstance(payload, dict) and payload.get("type") == "resize":
                        continue
                    raw_bytes = text.encode("utf-8", errors="ignore")
                except json.JSONDecodeError:
                    raw_bytes = text.encode("utf-8", errors="ignore")

            if raw_bytes:
                process.stdin.write(raw_bytes)
                await process.stdin.drain()

    try:
        await asyncio.gather(_stdout_to_ws(), _ws_to_stdin())
    except WebSocketDisconnect:
        pass
    finally:
        try:
            if process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2)
        except Exception:
            if process.returncode is None:
                process.kill()
        await websocket.close()


@router.get("/containers")
async def list_containers():
    STATE.ensure_background_threads()
    client = STATE.ensure_docker_client()
    if client is None:
        return {"containers": []}

    containers = []
    for container in client.containers.list(all=True):
        image = container.image.tags[0] if container.image.tags else container.image.short_id
        containers.append(
            {
                "id": container.short_id,
                "name": container.name,
                "image": image,
                "status": container.status,
            }
        )
    return {"containers": containers}


@router.post("/images/upload")
async def upload_image(file: UploadFile = File(...), memo: str = Form("")):
    del memo
    if not file.filename.lower().endswith(".tar"):
        return {"ok": False, "message": "Only .tar files can be uploaded."}

    client = STATE.ensure_docker_client()
    if client is None:
        return _docker_unavailable_response()

    unique_name = f"{uuid.uuid4()}_{Path(file.filename).name}"
    save_path = STATE.upload_dir / unique_name
    try:
        with save_path.open("wb") as handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                handle.write(chunk)

        result = subprocess.run(
            ["docker", "load", "-i", str(save_path)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            return {"ok": False, "message": f"docker load failed: {result.stderr[:240]}"}

        image_name = Path(file.filename).stem
        for line in result.stdout.splitlines():
            if "Loaded image:" in line:
                image_name = line.split("Loaded image:", 1)[1].strip()
                break

        return {"ok": True, "message": f"Image loaded: {image_name}", "image_name": image_name}
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "docker load timed out after 300 seconds."}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}
    finally:
        if save_path.exists():
            save_path.unlink(missing_ok=True)


@router.post("/containers/run")
async def run_container(request: RunRequest):
    STATE.ensure_background_threads()
    client = STATE.ensure_docker_client()
    if client is None:
        return _docker_unavailable_response()

    name = request.name.strip() or None
    secure_run_kwargs = {
        "detach": True,
        "name": name,
        "network_mode": "none",
        "mem_limit": "256m",
        "cpu_period": 100000,
        "cpu_quota": 50000,
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"],
        "pids_limit": 100,
    }

    try:
        container = client.containers.run(request.image, **secure_run_kwargs)
        fallback_used = False
    except Exception as secure_exc:
        try:
            container = client.containers.run(request.image, detach=True, name=name)
            fallback_used = True
            print(f"[dynamic] Secure run options failed, fallback used: {secure_exc}")
        except Exception as exc:
            return {"ok": False, "message": str(exc)}

    STATE.ensure_log_watch(container.name)
    message = f"Container started: {container.name}"
    if fallback_used:
        message += " (fallback mode)"
    return {"ok": True, "message": message, "name": container.name}


@router.post("/containers/action")
async def container_action(request: ActionRequest):
    STATE.ensure_background_threads()
    client = STATE.ensure_docker_client()
    if client is None:
        return _docker_unavailable_response()

    try:
        container = client.containers.get(request.name)
        if request.action == "start":
            container.start()
            STATE.ensure_log_watch(container.name)
        elif request.action == "stop":
            container.stop()
        elif request.action == "restart":
            container.restart()
            STATE.ensure_log_watch(container.name)
        elif request.action == "remove":
            container.remove(force=True)
        else:
            return {"ok": False, "message": f"Unsupported action: {request.action}"}
        return {"ok": True, "message": f"{request.action} completed: {request.name}"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


@router.post("/containers/exec")
async def container_exec(request: ExecRequest):
    STATE.ensure_background_threads()
    client = STATE.ensure_docker_client()
    if client is None:
        return {"ok": False, "output": "Docker is not connected on this host."}

    try:
        container = client.containers.get(request.name)
        result = container.exec_run(request.command, demux=False)
        output = result.output.decode("utf-8", errors="replace") if result.output else "(no output)"
        return {"ok": True, "output": output}
    except Exception as exc:
        return {"ok": False, "output": str(exc)}


@router.get("/health")
async def health():
    STATE.ensure_background_threads()
    client = STATE.ensure_docker_client()
    if client is None:
        return {"status": "degraded", "docker": False, "connections": len(STATE.alert_clients), "containers": []}

    return {
        "status": "ok",
        "docker": True,
        "connections": len(STATE.alert_clients),
        "containers": [container.name for container in client.containers.list(all=True)],
    }
