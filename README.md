# Custom OpenWrt Package Repository

This repository contains custom OpenWrt packages.

## Adding to OpenWrt

### 1. Download & Add Public Key

Download the signing key (`frab_openwrt.pub`) to trust packages from this repository:

```bash
wget -O /etc/apk/keys/frab_openwrt.pub https://francynox.github.io/frab-openwrt-repository/frab_openwrt.pub
```

### 2. Configure Repository Source

Add the repository URL corresponding to your OpenWrt architecture:

```text
https://francynox.github.io/frab-openwrt-repository/packages/<architecture>/packages.adb
```

Update package lists:

```bash
apk update
```

---

## Included Packages

| Package | Description |
| ------- | ----------- |
| `luci-app-firewall-hybrid` | Advanced Hybrid Firewall Status and Rules View for LuCI |

### Package Details

#### `luci-app-firewall-hybrid`
- **Description:** LuCI interface for managing OpenWrt firewall hybrid views (Port Forwards, Traffic Rules, SNATs, IP Sets).
- **Dependencies:** `luci-app-firewall`, `luci-base`
