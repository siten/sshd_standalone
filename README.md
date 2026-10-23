# sshd_standalone

基于 [russh](https://github.com/warp-tech/russh) 0.61 实现的轻量级 SSH 服务器，支持密码认证、交互式 shell、远程命令执行以及 SCP 文件传输（含递归）。可在桌面平台（Windows/Linux/macOS）、**Android** 和越狱 **iOS** 设备上运行。

## 功能

- **密码认证**（用户名 / 密码可配置）
- **交互式 shell**：`ssh user@host` 直接进入终端，基于真实 PTY，支持回显、提示符、行编辑、`vi`/`top` 等全屏程序、Ctrl+C、窗口大小自适应
- **远程命令执行**：`ssh user@host "<command>"`
- **SCP 文件传输**：上传、下载、递归（`scp -r`）创建/读取/写入文件和目录
- **持久化主机密钥**：首次启动生成并保存 Ed25519 主机密钥，重启后保持不变，客户端不会再报 “REMOTE HOST IDENTIFICATION HAS CHANGED” 警告

---

## 一、编译

### 1. 桌面平台（Windows / Linux / macOS）

```sh
cargo build --release
```

产物：`target/release/sshd_standalone`（Windows 为 `sshd_standalone.exe`）。

> 说明：本项目的 `russh` 已配置为使用纯 Rust 的 `ring` 加密后端（见 `Cargo.toml` 的 `default-features = false, features = ["ring", "flate2", "rsa"]`），**无需安装 NASM**，避免了默认 `aws-lc-rs` 后端在 Windows 上对 NASM 的依赖。

### 2. Android（交叉编译）

#### 前置条件

1. 安装 [cargo-ndk](https://github.com/bbqsrc/cargo-ndk)：

   ```sh
   cargo install cargo-ndk
   ```

2. 安装目标架构的 Rust 标准库（按需）：

   ```sh
   rustup target add armv7-linux-androideabi   # 32 位 arm (armeabi-v7a)
   rustup target add aarch64-linux-android      # 64 位 arm (arm64-v8a)
   ```

3. 安装 Android NDK，并设置环境变量 `ANDROID_NDK_HOME` 指向 NDK 根目录。

   - Windows PowerShell：
     ```powershell
     $env:ANDROID_NDK_HOME = "E:/Android/Sdk/ndk/<版本号>"
     ```
   - Linux / macOS：
     ```sh
     export ANDROID_NDK_HOME=/path/to/Android/Sdk/ndk/<版本号>
     ```

#### 编译命令

**必须加 `-P 23`**（指定 Android API level ≥ 23）：

```sh
# 32 位 (armeabi-v7a)
cargo ndk -P 23 -t armeabi-v7a build --release

# 64 位 (arm64-v8a)
cargo ndk -P 23 -t arm64-v8a build --release
```

产物：
- `target/armv7-linux-androideabi/release/sshd_standalone`
- `target/aarch64-linux-android/release/sshd_standalone`

> ⚠️ **关于 `-P 23`（重要）**
> 交互式 shell 依赖 `openpty()`，而 Android 的 Bionic libc 从 **API level 23（Android 6.0）** 起才提供该函数。cargo-ndk 默认使用 API 21，会导致链接错误 `undefined symbol: openpty`。因此必须用 `-P 23`，且**编译出的二进制需要运行在 Android 6.0 及以上的设备**。

> ⚠️ **关于 NDK 版本**
> 部分 NDK（如 r23 beta）的 arm64 缺少 `libunwind.a`，编译 `arm64-v8a` 时会报 `unable to find library -lunwind`。若遇到，请改用稳定版 NDK（如 r25( android-ndk-r25c-25.2.9519653 https://github.com/android/ndk/wiki/Unsupported-Downloads ) 或 r26），或先只编译 `armeabi-v7a`（其 `libunwind.a` 通常完整）。

### 3. 越狱 iOS（arm64 真机）

iOS 设备目标为 `aarch64-apple-ios`。**仅添加 Rust target 不够**：Rust 标准库可以通过 rustup 安装，但链接需要 macOS 上的 Xcode/iPhoneOS SDK。Windows 上不能只靠 `rustup target add` 生成可运行的 iPhone Mach-O。

在安装了**完整 Xcode**（包含 iPhoneOS SDK）的 macOS 上：

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
rustup target add aarch64-apple-ios
export SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
cargo build --release --target aarch64-apple-ios
```

产物：`target/aarch64-apple-ios/release/sshd_standalone`。这是 arm64 iOS **真机**目标，不是 iOS Simulator。常规情况下无需改 `Cargo.toml` 增加 target；target 是通过 `rustup target add` 安装，构建时用 `--target` 选择。首次构建应在 Mac/Xcode 环境完成，以确认当前依赖版本和 SDK 的链接兼容性。

仓库提供 `.github/workflows/build-ios.yml`：在 GitHub 仓库的 **Actions → Build iOS arm64 binary → Run workflow** 手动启动构建，完成后从 workflow run 的 Artifacts 下载 `sshd_standalone-ios-arm64`。CI 只负责生成二进制；越狱设备上的 adhoc entitlement 签名仍按下文执行。

#### 在 rootless 越狱设备部署

本项目已按 iOS rootless/rootful 布局查找 `sh`：依次检查 `/system/bin/sh`、`/var/jb/bin/sh`、`/var/jb/usr/bin/sh`、`/bin/sh`、`/usr/bin/sh`、`/usr/local/bin/sh`，最后回退到 PATH 中的 `sh`。交互式 PTY 和远程命令执行共用该查找逻辑。

host key 默认保存在可执行文件同目录的 `host_key` 文件中。传入 `--host-key PATH` 时先尝试指定路径；该路径不可用时回退到可执行文件同目录。两处都不可写时才使用仅驻留内存的临时密钥，并打印警告；这种情况下每次重启都会更换 SSH 主机身份。启动时会打印实际使用的文件绝对路径或临时密钥状态。守护进程的工作目录可能变化，因此 host key 按可执行文件位置确定，而不是当前工作目录。

iOS 越狱仍会对 Mach-O 执行代码签名检查。对已实测的 Dopamine rootless（iOS 15.8.5）设备，二进制需使用带 `com.apple.private.security.no-container` entitlement 的 adhoc 签名；未签名、裸 `ldid -S` 或仅加 trustcache 都无法运行。这里的签名不需要 Apple 开发者证书，但每次替换二进制后都要重新签名。其他越狱方案/版本的 AMFI 行为可能不同。

先在构建机创建 `sshd.entitlements`，内容如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.private.security.no-container</key><true/>
</dict></plist>
```

通过现有 SSH/SCP 将程序和 plist 放到设备可写目录，然后在手机上签名并启动：

```sh
ldid -S/var/jb/var/mobile/sshd.entitlements /var/jb/var/mobile/sshd_standalone
chmod +x /var/jb/var/mobile/sshd_standalone
/var/jb/var/mobile/sshd_standalone --port 2222 --user admin --password yourpassword \
  --host-key /var/jb/var/mobile/sshd_host_key
```

设备上的 `ldid` 可通过 Procursus 安装；对本次实测设备，`/var/jb/usr/bin/ldid` 已存在。端口 22 需要 root 权限，普通 `mobile` 用户使用 1024 以上端口（如 2222）。

---

## 二、运行

### 命令行参数

```
sshd_standalone [--host 0.0.0.0] [--port 2222] [--user admin] [--password password] [--host-key PATH]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `0.0.0.0` | 监听地址 |
| `--port` | `2222` | 监听端口 |
| `--user` | `admin` | 登录用户名 |
| `--password` | `password` | 登录密码 |
| `--host-key` | 可执行文件同目录的 `host_key` | 指定主机密钥文件；指定路径不可用时回退到可执行文件同目录，无可写路径时使用临时密钥 |

日志级别可用环境变量 `RUST_LOG` 控制（默认 `info`）。

### 桌面平台示例

```sh
./sshd_standalone --port 2222 --user admin --password yourpassword
```

### Android 示例

将编译好的二进制推送到设备并赋予可执行权限，注意 `--host-key` 指向**可写且持久**的目录（否则重启后主机密钥会丢失）：

```sh
# 在 PC 上推送
adb push target/armv7-linux-androideabi/release/sshd_standalone /data/local/tmp/

# 在设备 shell 中运行
adb shell
cd /data/local/tmp
chmod +x sshd_standalone
./sshd_standalone --port 2222 --user admin --password yourpassword --host-key /data/local/tmp/host_key
```

> 提示：非 root 环境下请使用 ≥1024 的端口（如 2222）。Android 上交互式 shell 走 `/dev/ptmx`，多数设备普通权限即可使用，无需 root。

---

## 三、客户端连接

假设服务器 IP 为 `192.168.1.100`，端口 `2222`，用户 `admin`。

### 1. 交互式 shell

```sh
ssh admin@192.168.1.100 -p 2222
```

输入密码后进入 shell，可正常打字、看到提示符、运行 `top`/`vi` 等。

### 2. 执行单条命令

```sh
ssh admin@192.168.1.100 -p 2222 "ls -l /sdcard"
```

### 3. SCP 文件传输

> **注意：现代 OpenSSH 的 `scp` 默认走 SFTP 协议**，**加 `-O`** 强制使用 经典SCP 协议模式。

```sh
# 上传单个文件
scp -O -P 2222 ./local.txt admin@192.168.1.100:/sdcard/remote.txt

# 递归上传目录
scp -O -r -P 2222 ./mydir admin@192.168.1.100:/sdcard/

# 下载单个文件
scp -O -P 2222 admin@192.168.1.100:/sdcard/remote.txt ./local.txt

# 递归下载目录
scp -O -r -P 2222 admin@192.168.1.100:/sdcard/mydir ./
```

---

## 四、项目结构

```
sshd_standalone/
├── Cargo.toml                  # 依赖配置（russh 使用 ring 后端）
├── src/
│   ├── main.rs                 # 服务器、认证、命令执行、交互式 PTY shell
│   ├── scp.rs                  # SCP 协议实现（上传 / 下载 / 递归）
│   └── sftp.rs                 # sftp 实现
└── examples/
    └── test_client.rs          # 集成测试客户端（程序化验证各功能）
```

### 运行集成测试

```sh
# 终端 1：启动服务器（默认端口 2222；测试客户端连接 2223，按需调整）
./sshd_standalone --port 2223 --user admin --password password

# 终端 2：运行测试客户端
cargo run --example test_client
```

---

## 安全提示

- 默认账号 `admin/password` 仅用于测试，正式使用请务必通过参数修改。
- 命令执行会直接交给系统 shell（`sh -c` / `cmd /C`），请勿暴露在不可信网络中。
- 主机密钥文件包含私钥，注意妥善保管（Unix 下自动设置为 `0600` 权限）。
