#!/usr/bin/env python3
"""AIH network.connector plugin: WireGuard.

Reports a WireGuard tunnel only when the interface is actually up. It never
claims direct P2P or DERP usage: WireGuard does not expose that distinction in
the local tooling, and a peer endpoint may itself be a relay.

Version is reported, never enforced. State lives under
$HOME/.ai_home/plugin-state/network.wireguard/ with 0600 config files.
"""
import atexit
import base64
import json
import os
import platform
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

PLUGIN_ID = "network.wireguard"
PLUGIN_VERSION = "0.1.2"
STATE_DIR = Path(os.environ.get("AIH_PLUGIN_STATE_DIR", Path.home() / ".ai_home" / "plugin-state" / PLUGIN_ID))
STATE_FILE = STATE_DIR / "state.json"
DEFAULT_STATE = {"enabled": False, "config": {}, "updatedAt": 0}
DEFAULT_INTERFACE = "wg0"
BASE_REQUIRED_FIELDS = ("privateKey", "address", "peerPublicKey", "allowedIPs")
DEFAULT_LOCAL_UDP_PORT = 51822
DEFAULT_REMOTE_UDP_PORT = 51821
SSH_PROBE_TIMEOUT = 20

# 远端中继脚本：stdin/stdout 走 SSH 通道，按 2 字节长度分帧；本地/远端都是环回 UDP，
# 不监听任何公网端口。
SSH_RELAY_SCRIPT = r"""
import os, select, socket, struct, sys
target = ("{target_host}", {target_port})
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", {bind_port}))
sock.setblocking(False)
out = sys.stdout.buffer

def write(data):
    out.write(struct.pack(">H", len(data)) + data)
    out.flush()

def read_exact(n):
    data = b""
    while len(data) < n:
        chunk = os.read(0, n - len(data))
        if not chunk:
            return None
        data += chunk
    return data

while True:
    r, _, _ = select.select([sock, 0], [], [])
    if sock in r:
        data, _ = sock.recvfrom(65535)
        write(data)
    if 0 in r:
        head = read_exact(2)
        if head is None:
            break
        size = struct.unpack(">H", head)[0]
        body = read_exact(size)
        if body is None:
            break
        sock.sendto(body, target)
"""

_TRANSPORTS = {}


def log(message):
    print(f"[{PLUGIN_ID}] {message}", file=sys.stderr, flush=True)


def load_state():
    try:
        data = json.loads(STATE_FILE.read_text())
        if isinstance(data, dict):
            merged = dict(DEFAULT_STATE)
            merged.update(data)
            if not isinstance(merged.get("config"), dict):
                merged["config"] = {}
            return merged
    except (OSError, ValueError):
        pass
    return dict(DEFAULT_STATE)


def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    state["updatedAt"] = int(time.time() * 1000)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    os.chmod(tmp, 0o600)
    tmp.replace(STATE_FILE)


def run(cmd, timeout=20, env=None):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                env={**os.environ, **(env or {})})
        return result.returncode, (result.stdout or "").strip(), (result.stderr or "").strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def proxy_env(state):
    proxy = str((state.get("config") or {}).get("proxyUrl") or "").strip()
    if not proxy:
        return {}
    return {
        "HTTPS_PROXY": proxy,
        "HTTP_PROXY": proxy,
        "ALL_PROXY": proxy,
        "https_proxy": proxy,
        "http_proxy": proxy,
        "all_proxy": proxy,
    }


def transport_mode(config):
    mode = str(config.get("transport") or "udp").strip().lower()
    return mode if mode in ("udp", "ssh") else "udp"


def port_value(config, key, default):
    raw = str(config.get(key) or "").strip()
    if raw.isdigit() and 0 < int(raw) <= 65535:
        return int(raw)
    return default


class SSHTransport:
    """把 WireGuard 的 UDP 报文经 SSH 通道转发，避免要求对端开放任何 UDP 端口。"""

    def __init__(self, command, local_port):
        self.alive = True
        self.last = None
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", local_port))
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, bufsize=0,
        )
        threading.Thread(target=self._udp_to_ssh, daemon=True).start()
        threading.Thread(target=self._ssh_to_udp, daemon=True).start()

    def _udp_to_ssh(self):
        while self.alive:
            try:
                data, addr = self.udp.recvfrom(65535)
            except OSError:
                return
            self.last = addr
            try:
                self.proc.stdin.write(struct.pack(">H", len(data)) + data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                return

    @staticmethod
    def _read_exact(stream, size):
        data = b""
        while len(data) < size:
            chunk = stream.read(size - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def _ssh_to_udp(self):
        stream = self.proc.stdout
        while self.alive:
            head = self._read_exact(stream, 2)
            if head is None:
                return
            size = struct.unpack(">H", head)[0]
            body = self._read_exact(stream, size)
            if body is None:
                return
            if self.last is not None:
                try:
                    self.udp.sendto(body, self.last)
                except OSError:
                    return

    def running(self):
        return self.alive and self.proc.poll() is None

    def stop(self):
        self.alive = False
        try:
            self.udp.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            try:
                self.proc.kill()
            except OSError:
                pass


def ssh_transport_command(config):
    host = str(config.get("sshHost") or "").strip()
    user = str(config.get("sshUser") or "").strip()
    peer = str(config.get("sshPeerUdp") or "").strip()
    if not host or not user or ":" not in peer:
        return None, "SSH 传输需要 sshHost、sshUser 与 sshPeerUdp（例如 127.0.0.1:51820）"
    target_host, target_port = peer.rsplit(":", 1)
    if not target_port.isdigit():
        return None, "sshPeerUdp 端口无效"
    bind_port = port_value(config, "remoteUdpPort", DEFAULT_REMOTE_UDP_PORT)
    script = SSH_RELAY_SCRIPT.format(
        target_host=target_host, target_port=int(target_port), bind_port=bind_port)
    encoded = base64.b64encode(script.encode()).decode()
    prefix = str(config.get("sshRemoteCommand") or "").strip() or "python3"
    remote_command = prefix + " -c \"import base64;exec(base64.b64decode('%s'))\"" % encoded
    args = [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
        "-o", "ConnectTimeout=10",
        "-p", str(port_value(config, "sshPort", 22)),
    ]
    identity = str(config.get("sshIdentityFile") or "").strip()
    if identity:
        args += ["-i", str(Path(identity).expanduser())]
    args += [user + "@" + host, remote_command]
    return args, ""


def start_ssh_transport(state):
    interface = interface_name(state)
    stop_ssh_transport(interface)
    config = state.get("config") or {}
    command, error = ssh_transport_command(config)
    if command is None:
        return None, error
    local_port = port_value(config, "localUdpPort", DEFAULT_LOCAL_UDP_PORT)
    try:
        transport = SSHTransport(command, local_port)
    except OSError as exc:
        return None, f"SSH 传输启动失败：{exc}"
    time.sleep(2.0)
    if not transport.running():
        transport.stop()
        return None, "SSH 传输启动后立即退出，请检查 sshHost、sshUser 与身份文件"
    _TRANSPORTS[interface] = transport
    return transport, ""


def stop_ssh_transport(interface):
    transport = _TRANSPORTS.pop(interface, None)
    if transport is not None:
        transport.stop()


def stop_all_transports():
    for interface in list(_TRANSPORTS):
        stop_ssh_transport(interface)


atexit.register(stop_all_transports)


def command_output(out, err, limit=20):
    text = (err or out or "").strip()
    if not text:
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return lines[-limit:]


def wg_path():
    return shutil.which("wg") or ""


def wg_quick_path():
    return shutil.which("wg-quick") or ""


def installed():
    return bool(wg_path() and wg_quick_path())


def tools_version():
    wg = wg_path()
    if not wg:
        return ""
    code, out, err = run([wg, "--version"], timeout=10)
    text = out or err
    if code != 0 or not text:
        return ""
    return text.splitlines()[0].strip()[:96]


def interface_name(state):
    raw = str((state.get("config") or {}).get("interfaceName") or DEFAULT_INTERFACE).strip()
    if not raw:
        raw = DEFAULT_INTERFACE
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=+.-")
    cleaned = "".join(ch for ch in raw if ch in allowed)[:15]
    return cleaned or DEFAULT_INTERFACE


def interface_up(name):
    if not name:
        return False
    if platform.system() == "Darwin":
        code, _, _ = run(["ifconfig", name], timeout=10)
        return code == 0
    code, _, _ = run(["ip", "link", "show", name], timeout=10)
    return code == 0


def config_complete(config):
    for key in BASE_REQUIRED_FIELDS:
        if not str(config.get(key) or "").strip():
            return False
    if transport_mode(config) == "ssh":
        for key in ("sshHost", "sshUser", "sshPeerUdp"):
            if not str(config.get(key) or "").strip():
                return False
        return True
    return bool(str(config.get("endpoint") or "").strip())


def config_file(state):
    return STATE_DIR / (interface_name(state) + ".conf")


def on_linux():
    return platform.system() == "Linux"


def system_config_path(state):
    return "/etc/wireguard/" + interface_name(state) + ".conf"


def install_system_config(path, state):
    """Linux: wg-quick 的 AppArmor 配置只放行 /etc/wireguard，把生成配置安装过去。"""
    code, out, err = run(["sudo", "-n", "install", "-d", "-m", "700", "/etc/wireguard"], timeout=30)
    if code == 0:
        code, out, err = run(["sudo", "-n", "install", "-m", "600", str(path), system_config_path(state)], timeout=30)
    return code, out, err


def write_config(state):
    config = state.get("config") or {}
    lines = ["[Interface]", f"PrivateKey = {str(config.get('privateKey') or '').strip()}"]
    address = str(config.get("address") or "").strip()
    if address:
        lines.append(f"Address = {address}")
    listen_port = str(config.get("listenPort") or "").strip()
    if listen_port.isdigit() and 0 < int(listen_port) <= 65535:
        lines.append(f"ListenPort = {int(listen_port)}")
    dns = str(config.get("dns") or "").strip()
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {str(config.get('peerPublicKey') or '').strip()}"]
    preshared = str(config.get("presharedKey") or "").strip()
    if preshared:
        lines.append(f"PresharedKey = {preshared}")
    endpoint = str(config.get("endpoint") or "").strip()
    if transport_mode(config) == "ssh":
        endpoint = "127.0.0.1:%d" % port_value(config, "localUdpPort", DEFAULT_LOCAL_UDP_PORT)
    lines.append(f"Endpoint = {endpoint}")
    lines.append(f"AllowedIPs = {str(config.get('allowedIPs') or '').strip()}")
    keepalive = str(config.get("persistentKeepalive") or "").strip()
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    path = config_file(state)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return path


def status_view(state=None):
    state = state or load_state()
    config = state.get("config") or {}
    name = interface_name(state)
    has_tools = installed()
    running = has_tools and interface_up(name)
    version = tools_version() if has_tools else ""
    if not has_tools:
        label = "未安装"
    elif not config_complete(config):
        label = "已安装，未配置"
    elif running:
        label = "运行中"
    else:
        label = "已停止"

    message = ""
    if not has_tools:
        message = "未找到 wg/wg-quick，可执行 install 通过 Homebrew 安装"
    elif not config_complete(config):
        message = "请先配置接口、私钥、对端公钥、Endpoint 与 AllowedIPs"
    elif not running:
        message = "配置已保存；执行 enable 需要管理员权限"
    if running and transport_mode(config) == "ssh" and name not in _TRANSPORTS:
        message = "SSH 传输中继未运行；请重新执行 enable"

    if running:
        connectivity = {
            "mode": "wireguard-tunnel",
            "confidence": "observed",
            "observedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": {"source": "ifconfig" if platform.system() == "Darwin" else "ip", "path": "interface", "transport": "wireguard"},
        }
    else:
        connectivity = {"mode": "unavailable", "confidence": "observed"}

    return {
        "installed": has_tools,
        "enabled": bool(state.get("enabled")) or running,
        "running": running,
        "state": label,
        "version": version,
        "message": message,
        "connectivity": connectivity,
    }


def describe():
    return {
        "schemaVersion": 1,
        "kind": "describe",
        "connector": {
            "id": "wireguard",
            "name": "WireGuard",
            "description": "本机 WireGuard 接口；只报告隧道是否启用，不推断直连 P2P 或中继",
            "transport": "wireguard",
            "operations": [
                {"id": "install", "label": "安装 wireguard-tools", "confirmation": "required"},
                {"id": "uninstall", "label": "卸载 wireguard-tools", "confirmation": "required"},
                {"id": "configure", "label": "配置接口与对端", "confirmation": "required"},
                {"id": "enable", "label": "启用 WireGuard", "confirmation": "required"},
                {"id": "disable", "label": "停用 WireGuard", "confirmation": "required"},
                {"id": "probe", "label": "探测接口状态", "confirmation": "none"},
            ],
            "config": {
                "schema": {
                    "type": "object",
                    "properties": {
                        "interfaceName": {"type": "string", "description": "接口名，默认 wg0"},
                        "transport": {"type": "string", "description": "udp（默认，直连对端）或 ssh（复用现有 SSH 通道，无需对端开放端口）"},
                        "sshHost": {"type": "string", "description": "SSH 传输：对端主机名或 IP"},
                        "sshPort": {"type": "string", "description": "SSH 传输：SSH 端口，默认 22"},
                        "sshUser": {"type": "string", "description": "SSH 传输：SSH 用户名"},
                        "sshIdentityFile": {"type": "string", "description": "SSH 传输：可选的私钥路径（缺省用 ssh-agent）"},
                        "sshPeerUdp": {"type": "string", "description": "SSH 传输：对端 WireGuard 的 UDP 地址，例如 127.0.0.1:51820"},
                        "sshRemoteCommand": {"type": "string", "description": "SSH 传输：远端执行前缀，默认 python3（可指定命名空间包装等）"},
                        "localUdpPort": {"type": "string", "description": "SSH 传输：本机中继 UDP 端口，默认 51822"},
                        "remoteUdpPort": {"type": "string", "description": "SSH 传输：对端中继 UDP 端口，默认 51821"},
                        "privateKey": {"type": "string", "description": "本机 WireGuard 私钥（base64）"},
                        "address": {"type": "string", "description": "接口地址，例如 10.0.0.2/32"},
                        "dns": {"type": "string", "description": "可选 DNS，例如 1.1.1.1"},
                        "peerPublicKey": {"type": "string", "description": "对端 WireGuard 公钥"},
                        "presharedKey": {"type": "string", "description": "可选预共享密钥"},
                        "endpoint": {"type": "string", "description": "对端 endpoint，例如 vpn.example.com:51820"},
                        "allowedIPs": {"type": "string", "description": "路由网段，例如 0.0.0.0/0, ::/0"},
                        "listenPort": {"type": "string", "description": "可选监听端口；需要被对端主动连接或在端口映射后使用，例如 51820"},
                        "persistentKeepalive": {"type": "string", "description": "可选保活秒数，例如 25"},
                        "proxyUrl": {"type": "string", "description": "安装使用的 HTTP(S) 或 SOCKS 代理"},
                    },
                },
                "secretFields": ["privateKey", "presharedKey", "proxyUrl"],
            },
            "connectivityModes": ["wireguard-tunnel", "unavailable"],
        },
    }


def configure(state, value):
    config = dict(state.get("config") or {})
    if isinstance(value, dict):
        if isinstance(value.get("value"), str):
            config["privateKey"] = value["value"].strip()
        for key in ("interfaceName", "privateKey", "address", "dns", "peerPublicKey",
                    "presharedKey", "endpoint", "allowedIPs", "listenPort", "persistentKeepalive", "proxyUrl",
                    "transport", "sshHost", "sshPort", "sshUser", "sshIdentityFile", "sshPeerUdp",
                    "sshRemoteCommand", "localUdpPort", "remoteUdpPort"):
            if isinstance(value.get(key), str):
                config[key] = value[key].strip()
    elif isinstance(value, str):
        config["privateKey"] = value.strip()
    config = {key: val for key, val in config.items() if str(val).strip()}
    state["config"] = config
    save_state(state)
    return {"ok": True, "changed": bool(config), "message": "配置已保存" if config else "配置为空", "status": status_view(state)}


def install(state):
    if installed():
        return {"ok": True, "changed": False, "message": "wireguard-tools 已安装", "status": status_view(state)}
    brew = shutil.which("brew")
    if not brew:
        if on_linux():
            return {"ok": False, "changed": False, "message": "Linux 请用发行版包管理器安装 wireguard-tools 后重试"}
        return {"ok": False, "changed": False, "message": "未找到 Homebrew；请手动安装 wireguard-tools 后重试"}
    code, out, err = run([brew, "install", "wireguard-tools"], timeout=600, env=proxy_env(state))
    output = command_output(out, err)
    if code != 0:
        log(err or out)
        reason = output[-1] if output else "Homebrew 安装失败"
        return {"ok": False, "changed": False, "message": "Homebrew 安装失败：" + reason[:200], "output": output}
    return {"ok": True, "changed": True, "message": "wireguard-tools 安装完成", "output": output, "status": status_view(state)}


def uninstall(state):
    if not installed():
        return {"ok": True, "changed": False, "message": "wireguard-tools 未安装", "status": status_view(state)}
    brew = shutil.which("brew")
    if not brew:
        return {"ok": False, "changed": False, "message": "未找到 Homebrew；请手动卸载 wireguard-tools"}
    code, out, err = run([brew, "uninstall", "wireguard-tools"], timeout=300, env=proxy_env(state))
    output = command_output(out, err)
    if code != 0:
        log(err or out)
        reason = output[-1] if output else "Homebrew 卸载失败"
        return {"ok": False, "changed": False, "message": "Homebrew 卸载失败：" + reason[:200], "output": output}
    return {"ok": True, "changed": True, "message": "wireguard-tools 已卸载", "output": output, "status": status_view(state)}


def sudo_message(output, action, path):
    text = "\n".join(output).lower()
    if "password is required" in text or "a password is required" in text or "sudo:" in text:
        return f"需要管理员权限：请在终端执行 sudo wg-quick {action} {path}"
    reason = output[-1] if output else "wg-quick 执行失败"
    return f"wg-quick {action} 失败：{reason[:200]}"


def enable(state):
    if not installed():
        return {"ok": False, "changed": False, "message": "wireguard-tools 尚未安装", "status": status_view(state)}
    config = state.get("config") or {}
    if not config_complete(config):
        return {"ok": False, "changed": False, "message": "配置不完整：需要私钥、地址、对端公钥、Endpoint 与 AllowedIPs", "status": status_view(state)}
    path = write_config(state)
    if transport_mode(config) == "ssh":
        _, transport_error = start_ssh_transport(state)
        if transport_error:
            return {"ok": False, "changed": False, "message": transport_error,
                    "status": status_view(state)}
    if on_linux():
        code, out, err = install_system_config(path, state)
        if code == 0:
            # 按接口名启动，wg-quick 会读取 /etc/wireguard/<iface>.conf。
            code, out, err = run(["sudo", "-n", wg_quick_path(), "up", interface_name(state)], timeout=90)
        target = system_config_path(state)
    else:
        code, out, err = run(["sudo", "-n", wg_quick_path(), "up", str(path)], timeout=90)
        target = str(path)
    output = command_output(out, err)
    if code != 0:
        log(err or out)
        stop_ssh_transport(interface_name(state))
        return {"ok": False, "changed": False, "message": sudo_message(output, "up", target), "output": output, "status": status_view(state)}
    state["enabled"] = True
    save_state(state)
    return {"ok": True, "changed": True, "message": "WireGuard 已启用", "output": output, "status": status_view(state)}


def disable(state):
    if not installed():
        return {"ok": False, "changed": False, "message": "wireguard-tools 尚未安装", "status": status_view(state)}
    path = config_file(state)
    before = status_view(state).get("running")
    if not before:
        stop_ssh_transport(interface_name(state))
        state["enabled"] = False
        save_state(state)
        return {"ok": True, "changed": False, "message": "WireGuard 未在运行", "status": status_view(state)}
    if on_linux():
        target = interface_name(state)
        code, out, err = run(["sudo", "-n", wg_quick_path(), "down", target], timeout=60)
        if code == 0:
            run(["sudo", "-n", "rm", "-f", system_config_path(state)], timeout=30)
        display = system_config_path(state)
    else:
        code, out, err = run(["sudo", "-n", wg_quick_path(), "down", str(path)], timeout=60)
        display = str(path)
    output = command_output(out, err)
    if code != 0:
        log(err or out)
        return {"ok": False, "changed": False, "message": sudo_message(output, "down", display), "output": output, "status": status_view(state)}
    stop_ssh_transport(interface_name(state))
    state["enabled"] = False
    save_state(state)
    return {"ok": True, "changed": True, "message": "WireGuard 已停用", "output": output, "status": status_view(state)}


def operate(action, value):
    state = load_state()
    if action == "install":
        return install(state)
    if action == "uninstall":
        return uninstall(state)
    if action == "configure":
        return configure(state, value)
    if action == "enable":
        return enable(state)
    if action == "disable":
        return disable(state)
    if action == "probe":
        return {"ok": True, "changed": False, "message": "探测完成", "status": status_view(state)}
    return {"ok": False, "changed": False, "message": f"未声明的操作：{action}"}


def handle_invoke(value):
    if not isinstance(value, dict):
        return describe()
    kind = value.get("kind")
    if kind == "describe":
        return describe()
    if kind == "status":
        return {"schemaVersion": 1, "kind": "status", "status": status_view()}
    if kind == "operate":
        return operate(str(value.get("action") or ""), value.get("input"))
    return describe()


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            continue
        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params") or {}
        if method == "invoke":
            result = handle_invoke(params.get("value"))
        elif method == "prepare":
            result = {"state": "prepared"}
        elif method == "activate":
            result = {"state": "active"}
        elif method == "dispose":
            result = {"state": "disposed"}
        elif method == "ping":
            result = {"ok": True}
        elif method == "shutdown":
            result = {"state": "disposed"}
        else:
            result = {"ok": False, "message": f"unknown method: {method}"}
        print(json.dumps({"id": request_id, "result": result}, ensure_ascii=False), flush=True)
        if method in ("dispose", "shutdown"):
            return


if __name__ == "__main__":
    main()
