# sshd_standalone

基于 [russh](https://github.com/warp-tech/russh) 0.65 的轻量 SSH 服务器。支持密码、公钥和 OpenSSH 用户证书登录，以及交互式 shell、远程命令、SFTP 和经典 SCP。可在 Windows、Linux、macOS、Android 和越狱 iOS 上运行。

`russh` 使用纯 Rust 的 `ring` 后端（`default-features = false, features = ["ring", "flate2", "rsa"]`），Windows 上不需要 NASM。

## 编译

桌面平台：

```sh
cargo build --release
```

产物是 `target/release/sshd_standalone`（Windows 为 `sshd_standalone.exe`）。

### Android

需要 [cargo-ndk](https://github.com/bbqsrc/cargo-ndk)、对应 target，以及 `ANDROID_NDK_HOME` 指向 NDK 根目录。PowerShell 示例：`$env:ANDROID_NDK_HOME = "E:/Android/Sdk/ndk/<版本>"`。

```sh
cargo install cargo-ndk
rustup target add armv7-linux-androideabi aarch64-linux-android
cargo ndk -P 23 -t armeabi-v7a build --release
cargo ndk -P 23 -t arm64-v8a build --release
```

必须使用 `-P 23`。交互式 shell 依赖 `openpty()`，Android 从 API 23 才提供它；cargo-ndk 默认的 API 21 会报 `undefined symbol: openpty`。二进制也要在 Android 6.0 及以上运行。

产物：

- `target/armv7-linux-androideabi/release/sshd_standalone`
- `target/aarch64-linux-android/release/sshd_standalone`

部分 NDK（如 r23 beta）的 arm64 缺少 `libunwind.a`。遇到 `unable to find library -lunwind` 时改用 r25c 或 r26，或先只编译 `armeabi-v7a`。

推到设备后，`--host-key` 指向可写且重启后仍在的路径。非 root 使用 1024 以上端口。交互式 shell 走 `/dev/ptmx`，多数设备不需要 root。

```sh
adb push target/armv7-linux-androideabi/release/sshd_standalone /data/local/tmp/
adb shell
cd /data/local/tmp && chmod +x sshd_standalone
./sshd_standalone --port 2222 --user admin --password yourpassword --host-key /data/local/tmp/host_key
```

### 越狱 iOS

目标是 `aarch64-apple-ios` 真机，不是 Simulator。只加 Rust target 不够，链接需要 macOS 上的完整 Xcode 和 iPhoneOS SDK。

```sh
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
rustup target add aarch64-apple-ios
export SDKROOT="$(xcrun --sdk iphoneos --show-sdk-path)"
cargo build --release --target aarch64-apple-ios
```

也可以在 GitHub 上打开 **Actions → Build iOS arm64 binary → Run workflow**，从 Artifacts 下载 `sshd_standalone-ios-arm64`。CI 不负责签名。

Dopamine rootless（已在 iOS 15.8.5 上试过）要求带 `com.apple.private.security.no-container` 的 adhoc 签名。未签名、裸 `ldid -S` 或只加 trustcache 都不能运行。不需要 Apple 开发者证书，但每次换二进制都要重新签名。其他越狱的 AMFI 行为可能不同。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
    <key>com.apple.private.security.no-container</key><true/>
</dict></plist>
```

```sh
ldid -S/var/jb/var/mobile/sshd.entitlements /var/jb/var/mobile/sshd_standalone
chmod +x /var/jb/var/mobile/sshd_standalone
/var/jb/var/mobile/sshd_standalone --port 2222 --user admin --password yourpassword \
  --host-key /var/jb/var/mobile/sshd_host_key
```

`ldid` 可用 Procursus 安装。端口 22 需要 root，普通 `mobile` 用户用 1024 以上端口。可执行文件旁边往往不可写，`--host-key` 要放在重启后仍在的目录。

## 运行

```
sshd_standalone [--host 0.0.0.0] [--port 2222] [--user admin] [--password password] [--host-key PATH] [--config PATH]
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `0.0.0.0` | 监听地址 |
| `--port` | `2222` | 监听端口 |
| `--user` | `admin` | 登录用户名。有 `--config` 时忽略 |
| `--password` | `password` | 登录密码。有 `--config` 时忽略 |
| `--host-key` | 可执行文件旁的 `host_key` | 服务器 Ed25519 主机身份，不是用户登录公钥 |
| `--config` | 无 | 服务器配置。指定后只启用文件里写对的登录方式 |
| `--help`、`-h` | | 打印用法后退出，状态码 0 |

命令行优先于配置文件，配置文件优先于上表的默认值。每个参数都要带一个值。缺值、空值、以 `--` 开头的值、重复参数和未知参数会拒绝启动，退出码为 2。日志级别用 `RUST_LOG`，默认 `info`。

```sh
./sshd_standalone --port 2222 --user admin --password yourpassword
```

### 配置文件

不带 `--config` 时只有一对用户名和密码。`--config` 的路径任意。空文件、空值、非法端口、未知段、写错的密钥，以及段外的其他文字，都会拒绝启动。重复的段、`host`、`port`、`host-key` 和密码用户也会拒绝启动，并在错误里写出重复内容；密码本身不打印。

三种登录方式互不影响，段里有有效条目才打开。空段、省略的段，以及空行和 `#` 开头的行，都不算条目。`host`、`port`、`host-key` 写在任何段之前；写进 `[passwords]` 时它们是用户名。

```
host = "0.0.0.0"
port = 2222
host-key = "host_key"

[public_keys]
ssh-ed25519 AAAA... comment

[certificates]
ssh-ed25519 AAAA... comment

[passwords]
alice = "secret"
```

示例是 `examples/server.conf`。公钥和 CA 都是 OpenSSH 一行一条；RFC 4716、PEM 和 X.509 不接受。列出的公钥可以用任意用户名登录。`[certificates]` 放的是 CA 公钥。客户端证书要由其中一把签发，principal 必须包含登录名，且当前时间在证书有效期内；critical options 非空的证书会拒绝。交互式 shell 会分配 PTY，因此证书还必须包含空值的 `permit-pty` extension；没有该 extension 的证书仍可用于不需要 PTY 的远程命令和 SFTP。主机证书和空 principal 会拒绝。任一启用的认证方式成功即可登录。

配置值可不加引号，或用双引号包裹；双引号内支持 `\\` 和 `\"` 转义。未闭合或内部未转义的双引号会拒绝启动。

### 主机密钥

顺序是命令行 `--host-key`、配置文件里的 `host-key`、可执行文件旁边的 `host_key`。命令行的相对路径按启动时的工作目录解析，配置文件里的相对路径按该文件所在目录解析。两个候选相同就只试一次。已有文件能读就用，读不出就跳过，不覆盖；没有文件就创建。都不可用时改用内存密钥，并打印警告，重启后主机身份会变。用了文件时，启动会打印它的绝对路径。Unix 上新建文件会尽量设为 `0600`，设权限失败仍会启动。

### Shell

交互式会话使用真实 PTY，窗口变化和 Ctrl+C 会交给这个终端。Unix 上它和远程命令用同一个程序，按这个顺序取第一个存在的文件：`/var/jb/usr/bin`、`/bin`、`/usr/bin`、`/usr/local/bin` 里的 `zsh`，然后是同样四个目录里的 `bash`，然后是 `/system/bin/sh`、`/var/jb/bin/sh`、`/var/jb/usr/bin/sh`、`/bin/sh`、`/usr/bin/sh`、`/usr/local/bin/sh`。都没有时用 `PATH` 中的 `sh`。交互式会话加 `-i`，远程命令加 `-c`。Windows 的交互式会话是 `cmd.exe`，远程命令是 `cmd.exe /C`。

工作目录先用存在的 `USERPROFILE`（仅 Windows），再用存在的 `HOME`。都没有时 Windows 用 `C:\`，其他系统用 `/`。登录名不参与选择。

## 客户端

下面假设服务器是 `192.168.1.100:2222`，用户 `admin`。

```sh
ssh admin@192.168.1.100 -p 2222
ssh admin@192.168.1.100 -p 2222 "ls -l /sdcard"
sftp -P 2222 admin@192.168.1.100
scp -P 2222 ./local.txt admin@192.168.1.100:/sdcard/remote.txt
scp -O -r -P 2222 ./mydir admin@192.168.1.100:/sdcard/
```

OpenSSH 的 `scp` 默认走 SFTP，这里直接支持。`-O` 改走经典 SCP。两种都能上传、下载和递归复制。

## 测试

```sh
cargo test
```

测试在进程内启动服务器，覆盖口令、公钥、用户证书、远程命令、经典 SCP、交互式 shell、SFTP，以及通道关闭后的清理。

源码在 `src/main.rs`、`server_config.rs`、`scp.rs`、`sftp.rs`。`session_tests.rs` 只在 `cargo test` 时编译。

## 安全

默认账号 `admin` / `password` 只在没有 `--config` 时生效，仅用于测试。配置文件里的密码是明文。远程命令会交给上面选定的 shell，不要把服务暴露到不可信网络。主机密钥文件含私钥。
