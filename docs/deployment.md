# Deploying the Mewtwo web dashboard safely

The dashboard has **no authentication** — the network boundary *is* the security control.
So the rules are simple: keep it on loopback, and reach it over a tunnel, never by exposing
the port.

---

## Security model (what protects it)

1. **Loopback bind** — `mewtwo serve` binds `127.0.0.1` by default. The socket never listens
   on a routable interface, so no other machine can connect. This is the primary control.
2. **Host-header allowlist** — requests are rejected unless the `Host` header is a loopback
   name (`localhost` / `127.0.0.1`). Browsers can't forge the `Host` header, so this defeats
   **DNS-rebinding** (a malicious site that re-points its domain at `127.0.0.1` still sends
   `Host: evil.com`, which is rejected).
3. **Loopback client guard** — while bound to localhost, any request whose peer IP is not
   `127.0.0.1`/`::1` is refused (defence in depth).
4. **No CORS** — no CORS headers are sent, so the same-origin policy blocks any cross-origin
   site from reading the API.
5. **Secrets stay server-side** — `ANTHROPIC_API_KEY` and scan auth are never sent to the
   browser; the UI only sees `configured: true/false`.

What it is **not** safe from: being bound to a routable address with `--host`. Don't.

---

## Recommended setup: Linux VM + NAT + SSH tunnel

Run Mewtwo inside a disposable Linux VM (isolates the payload-firing tooling from your host,
and you can snapshot/revert per engagement), and reach the dashboard from your host browser
through an SSH tunnel.

### 1. In the VM

```bash
sudo apt install openssh-server          # once
git clone https://github.com/MithunSreeram/Mewtwo.git && cd Mewtwo
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[web]'
mewtwo serve --no-open                    # stays bound to 127.0.0.1 inside the VM
ip a                                      # note the VM's IP (e.g. 192.168.x.x)
```

Use **NAT** networking in VMware: the VM gets outbound internet (recon needs crt.sh, the
Wayback CDX API, and the target), and your host can still reach the VM's IP over SSH.

### 2. On your host (Windows PowerShell or macOS/Linux terminal)

```bash
ssh -L 8000:localhost:8000 youruser@<vm-ip>
```

Leave that session open, then browse to **http://localhost:8000** on your host.

Why this is safe: the Mewtwo server only ever listens on the VM's loopback. The SSH tunnel
carries your host's `localhost:8000` into the VM over an encrypted, authenticated channel.
The request arrives at Mewtwo as `Host: localhost` from client `127.0.0.1`, so it passes both
guards. Nothing is exposed on any network except the VM's SSH daemon (port 22).

---

## If you really must expose it (not recommended)

Only on a trusted, isolated network, and understand it's unauthenticated:

```bash
mewtwo serve --host 0.0.0.0 --allow-host <vm-ip>
```

`--host 0.0.0.0` disables the loopback guard (you've opted into non-loopback clients), and
`--allow-host <vm-ip>` adds that IP to the Host allowlist so `http://<vm-ip>:8000` is accepted.
Anyone who can reach that IP:port can drive scans and read findings. The SSH tunnel above
avoids all of this — prefer it.

---

## Quick reference

| Goal | Command |
|------|---------|
| Normal local use | `mewtwo serve` (opens browser) |
| Headless / server | `mewtwo serve --no-open` |
| Host browser → VM | VM: `mewtwo serve --no-open` · Host: `ssh -L 8000:localhost:8000 user@vm` |
| Direct exposure (risky) | `mewtwo serve --host 0.0.0.0 --allow-host <ip>` |
