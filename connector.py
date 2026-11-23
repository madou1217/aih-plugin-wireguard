#!/usr/bin/env python3
"""AIH network.connector plugin: WireGuard.

Reports a WireGuard tunnel only when the interface is actually up. It never
claims direct P2P or DERP usage: WireGuard does not expose that distinction in
the local tooling, and a peer endpoint may itself be a relay.

Version is reported, never enforced. State lives under
$HOME/.ai_home/plugin-state/network.wireguard/ with 0600 config files.
"""
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_ID = "network.wireguard"
PLUGIN_VERSION = "0.1.1"
STATE_DIR = Path(os.environ.get("AIH_PLUGIN_STATE_DIR", Path.home() / ".ai_home" / "plugin-state" / PLUGIN_ID))
STATE_FILE = STATE_DIR / "state.json"
DEFAULT_STATE = {"enabled": False, "config": {}, "updatedAt": 0}
DEFAULT_INTERFACE = "wg0"
REQUIRED_FIELDS = ("privateKey", "address", "peerPublicKey", "endpoint", "allowedIPs")


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
    for key in REQUIRED_FIELDS:
        if not str(config.get(key) or "").strip():
            return False
    return True


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
    dns = str(config.get("dns") or "").strip()
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {str(config.get('peerPublicKey') or '').strip()}"]
    preshared = str(config.get("presharedKey") or "").strip()
    if preshared:
        lines.append(f"PresharedKey = {preshared}")
    lines.append(f"Endpoint = {str(config.get('endpoint') or '').strip()}")
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
                        "privateKey": {"type": "string", "description": "本机 WireGuard 私钥（base64）"},
                        "address": {"type": "string", "description": "接口地址，例如 10.0.0.2/32"},
                        "dns": {"type": "string", "description": "可选 DNS，例如 1.1.1.1"},
                        "peerPublicKey": {"type": "string", "description": "对端 WireGuard 公钥"},
                        "presharedKey": {"type": "string", "description": "可选预共享密钥"},
                        "endpoint": {"type": "string", "description": "对端 endpoint，例如 vpn.example.com:51820"},
                        "allowedIPs": {"type": "string", "description": "路由网段，例如 0.0.0.0/0, ::/0"},
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
                    "presharedKey", "endpoint", "allowedIPs", "persistentKeepalive", "proxyUrl"):
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
