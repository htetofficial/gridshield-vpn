# GridShield VPN — Sudoku 4×4 O(1) Obfuscated VPN App

[SUDOKU-ASCII/sudoku](https://github.com/SUDOKU-ASCII/sudoku) ၏ **4×4 Sudoku O(1) Traffic Obfuscation Protocol** ကို အခြေခံပြီး အမြန်ဆုံး Compiled Programming Languages (**Go** + **Native Swift / SwiftUI**) ဖြင့် တည်ဆောက်ထားသော Cross-Platform VPN App ဖြစ်ပါသည်။

## Architecture & Why Go + Swift?

| Component | Language | Purpose |
|---|---|---|
| **VPN Core Engine + CLI + Embedded Web Dashboard** (`dist/gridshield`) | **Go** (100% compiled native binary) | 4×4 Sudoku O(1) bitset codec (`prefer_ascii` / `prefer_entropy` / directional / custom XVP), Ed25519 Master/Split keys, X25519 PFS + HKDF + ChaCha20-Poly1305 / AES-128-GCM, HTTPMask (`auto`/`ws`/`stream`/`poll`/`legacy`), UDP-over-TCP (UoT), single-port SOCKS5 + HTTP proxy, OS System Proxy, gVisor userspace TCP/IP **TUN** (`utun`/`tun`/`wintun`), built-in Sudoku Server, and zero-dependency embedded Web Dashboard (`http://127.0.0.1:9099`). |
| **Native macOS Desktop + Menu Bar App** (`dist/GridShieldVPN.app`) | **Swift 6 + SwiftUI + AppKit** | Zero Electron overhead, instant launch, native Menu Bar status monitor (`MenuBarExtra`), live Canvas throughput graph, node profiles, `sudoku://` link import/export, built-in Server & KeyGen UI, and bundled Go core daemon. |

> **100% Wire-Compatible:** Official `SUDOKU-ASCII/sudoku` servers, `sudoku://` share links, `Sudodroid`, `Anywhere Proxy`, and `Mihomo/ClashMeta` များနှင့် တိုက်ရိုက် ချိတ်ဆက်အသုံးပြုနိုင်ပါသည်။

---

## Quick Start

### 1. Native macOS App ဖွင့်ရန် (Double-click or Terminal)
```bash
make build-macos
open dist/GridShieldVPN.app
```

### 2. CLI + Built-in Fast Web Dashboard (macOS / Linux / Windows)
```bash
make build-core
./dist/gridshield daemon --open
```
Dashboard ကို `http://127.0.0.1:9099` မှာ တိုက်ရိုက်ဖွင့်ပြီး **⚡ Quick Local Demo** ခလုတ်ကို နှိပ်ရုံဖြင့် Built-in Sudoku Server + Client ကို ချက်ချင်း ချိတ်ဆက်စမ်းသပ်နိုင်ပါသည်။

### 3. CLI Direct Usage

```bash
# Ed25519 Master + Split Client Key ထုတ်ရန်
./dist/gridshield keygen

# Sudoku VPN Server စတင်ရန် (Key auto-generate + sudoku:// link ထုတ်ပေးမည်)
./dist/gridshield server --port 8443 --ascii prefer_entropy --httpmask auto --public-host YOUR_SERVER_IP

# Client ချိတ်ဆက်ရန် — System Proxy Mode (Root/sudo မလိုပါ)
./dist/gridshield up --link "sudoku://..." --sysproxy

# Client ချိတ်ဆက်ရန် — Full-Device TUN VPN Mode (utun / tun0)
sudo ./dist/gridshield up --link "sudoku://..." --tun

# End-to-End 4x4 Sudoku Tunnel Benchmark & Wire Obfuscation Inspection
./dist/gridshield selftest --ascii prefer_ascii --aead chacha20-poly1305 --httpmask auto
./dist/gridshield selftest --ascii prefer_entropy --aead aes-128-gcm --httpmask ws
```

### 4. Cross-Compile (macOS / Linux / Windows)
```bash
make build-all
```

### 5. Automated Tests
```bash
make test
```

## License Note
This project integrates public protocol packages from `github.com/SUDOKU-ASCII/sudoku` (GPLv3) and `github.com/xjasonlyu/tun2socks/v2`. GridShield VPN is an independent client/server application and is not officially affiliated with the upstream project.
