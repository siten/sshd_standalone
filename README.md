# sshd_standalone

基于 [russh](https://github.com/warp-tech/russh) 0.61 实现的轻量级 SSH 服务器，支持密码认证、交互式 shell、远程命令执行以及 SCP 文件传输（含递归）。可在桌面平台（Windows/Linux/macOS）和 **Android** 上运行。

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

---

## 二、运行

### 命令行参数

```
sshd_standalone [--host 0.0.0.0] [--port 2222] [--user admin] [--password password] [--host-key host_key]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `0.0.0.0` | 监听地址 |
| `--port` | `2222` | 监听端口 |
| `--user` | `admin` | 登录用户名 |
| `--password` | `password` | 登录密码 |
| `--host-key` | `host_key` | 主机密钥文件路径，不存在则自动生成并保存 |

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
