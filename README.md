# aih-plugin-wireguard

AIH `network.connector` plugin for **WireGuard**.

- Connector id: `wireguard`
- Operations: `install`, `uninstall`, `configure`, `enable`, `disable`, `probe`
- Version is reported, never enforced. `engines.aih` is wide (`>=0.0.0`).

## What it does

- Detects `wg` / `wg-quick` and reports the tools version.
- Stores interface config under `$HOME/.ai_home/plugin-state/network.wireguard/`
  (directory 0700, config 0600).
- Generates a standard `wg-quick` config and runs:
  - `sudo -n wg-quick up <config>` on enable;
  - `sudo -n wg-quick down <config>` on disable.
- If sudo needs a password, enable fails with an explicit terminal instruction;
  it never pretends the tunnel is up.
- `install` / `uninstall` use Homebrew (`wireguard-tools`) and return the
  command output for the WebUI log panel.

## Connectivity reporting

| Mode | Evidence |
|---|---|
| `wireguard-tunnel` | the configured interface exists (`ifconfig` / `ip link`) |
| `unavailable` | tools/config missing, or the interface is down |

This plugin deliberately **does not** report `direct-p2p` or `derp-relay`:
WireGuard local tooling does not distinguish a direct peer from a relayed
endpoint, so claiming P2P would be unsupported.

## Install

Via WebUI: configure `proxyUrl` first if the Server process has no outbound
network, then click install. Progress and Homebrew output are shown in the
connector card.

Via CLI:

```sh
aih plugin install ./wireguard-0.1.0.aih-plugin \
  --trust-key ./public.pem \
  --expect-fingerprint 3960e945419f8f267c3f47b1
```

## Configure

```json
{
  "interfaceName": "wg0",
  "privateKey": "<base64 private key>",
  "address": "10.0.0.2/32",
  "dns": "1.1.1.1",
  "peerPublicKey": "<base64 peer public key>",
  "presharedKey": "<optional>",
  "endpoint": "vpn.example.com:51820",
  "allowedIPs": "0.0.0.0/0, ::/0",
  "listenPort": "51820",
  "persistentKeepalive": "25",
  "proxyUrl": "socks5h://127.0.0.1:1080"
}
```

`privateKey`, `presharedKey` and `proxyUrl` are secret fields; status responses
never echo them.

### SSH transport (no inbound port required)

If the peer cannot accept inbound UDP (NAT / carrier-grade NAT / cloud security
group), reuse an existing SSH account instead of opening a port:

```json
{
  "interfaceName": "wg0",
  "transport": "ssh",
  "sshHost": "peer.example.com",
  "sshPort": "22",
  "sshUser": "ubuntu",
  "sshIdentityFile": "~/.ssh/id_ed25519",
  "sshPeerUdp": "127.0.0.1:51820",
  "privateKey": "...",
  "address": "10.0.0.2/32",
  "peerPublicKey": "...",
  "allowedIPs": "10.0.0.1/32"
}
```

The plugin starts `ssh` to the peer and carries WireGuard's UDP datagrams over
that connection (length-prefixed over stdin/stdout), with loopback UDP ports on
both ends (`localUdpPort` 51822, `remoteUdpPort` 51821). Nothing listens on a
public interface; only the SSH port the host already exposes is used. The peer
must point its WireGuard `Endpoint` at `127.0.0.1:<remoteUdpPort>`.

## Boundaries

- Enabling/disabling requires `sudo -n`; interactive password prompts are not
  supported from the plugin process.
- On Linux the generated config is installed to `/etc/wireguard/<iface>.conf`
  before `wg-quick up <iface>`, because the shipped AppArmor profile only
  allows `wg-quick` to read that directory; the copy is removed on disable.
- macOS may additionally require the WireGuard userspace implementation or the
  WireGuard app; failures are returned verbatim.
- No Electron, WebView, CDP, or traffic interception.
