# StegoBox

An Android application that embeds arbitrary data — files, archives, or plain text — inside an
image, protected with authenticated encryption.

The project is deliberately stated without exaggeration. It does not claim to be undetectable,
and it does not claim that a hidden payload survives image re-processing. The limitations section
below describes exactly what the tool does and does not provide.

---

## English

### Overview

StegoBox packs a payload into a carrier image and restores it later. The payload is compressed,
encrypted, and integrity-checked before it is stored, so extracting the container does not reveal
its contents without the password.

Two carriers are available, with very different properties:

| Carrier | Location of the payload | Capacity | Survives re-encoding |
|---|---|---|---|
| Tail-append | Appended after the image bytes | Unlimited, bounded only by file size | No |
| Pixel LSB | Least significant bits of the R/G/B channels | `width x height x 3 / 8` bytes | No |

Neither carrier is designed to resist image processing. Any re-encode, thumbnail generation, or
platform transcode removes the payload. Payloads are therefore intended for lossless channels
(direct file transfer, storage, local network).

### Cryptography

All primitives are provided by Bouncy Castle through its lightweight API. No JCE provider is
registered, which avoids conflicts with the provider Android ships.

- Ciphers: AES-256-GCM, ChaCha20-Poly1305, SM4-GCM, or no encryption
- Key derivation: PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt
- Nonce: random 12 bytes per container
- Integrity: SHA-256 of the plaintext, in addition to the AEAD authentication tag

### Key and receive modes

Key mode determines how the password is produced:

| Key mode | Behaviour |
|---|---|
| Manual password | The user supplies the password; the receiver supplies it again |
| Random password | The application generates a 16-character password, which can be displayed or copied |
| No password | Encryption is disabled; only the SHA-256 integrity check remains |

Receive mode determines how the receiver obtains the password:

| Receive mode | Behaviour |
|---|---|
| Manual entry | The container is encrypted with the password and the receiver must enter it |
| Automatic entry | The password is stored inside the container. The receiver needs no input, but the container is not confidential: anyone holding the file can decrypt it |

### Container format (version 3)

```
magic        5 bytes   "SGBX3"
version      1 byte
carrier      1 byte    0 = tail-append, 1 = pixel LSB
cipher       1 byte    0 = none, 1 = AES-GCM, 2 = ChaCha20-Poly1305, 3 = SM4-GCM
keyMode      1 byte    0 = none, 1 = password, 2 = embedded
iterations   4 bytes   big-endian
salt        16 bytes
nonce       12 bytes
payloadLen   8 bytes   big-endian, length of the stored payload (ciphertext plus tag)
sha256      32 bytes   digest of the plaintext
nameLen      2 bytes   big-endian
name         n bytes   UTF-8; empty when the payload is a multi-file bundle
passwordLen  2 bytes   present only when keyMode = embedded
password     n bytes
payload      payloadLen bytes
```

### Features

- Any payload is accepted and treated as a byte stream: documents, images, archives, applications
- Multiple files are packed into a ZIP archive with automatically de-duplicated entry names
- Restoration preserves the original file name for single files and the directory structure for bundles
- Payloads are processed as streams through a temporary file, so hiding or extracting a file of
  several hundred megabytes does not exhaust memory
- Pixel LSB output is analysed with a chi-square test and the estimated detectability is reported
  in the log, so the user is told how visible the embedding is rather than being reassured
- Output can be written to a chosen directory, or directly to `Download/StegoBox` when the
  all-files access permission has been granted
- A self-test screen exercises every cipher and key mode, including the tail-append and LSB paths

### Building

Requirements: JDK 17, Android SDK with platform 35 and matching build tools, and the Gradle
wrapper included in the repository (Gradle 8.9, Android Gradle Plugin 8.7.3).

```
./gradlew :app:assembleRelease
```

Release signing must be configured in `app/build.gradle` with a keystore of your own.

Note for restricted environments: the `aapt2` binary bundled with the Android Gradle Plugin may
fail to start inside containers without a compatible loader. In that case point the build at a
working binary, for example:

```
android.aapt2FromMavenOverride=/usr/bin/aapt2
```

### Limitations

- The container is not stealthy. The magic string and the payload are visible with a hex editor
  or `strings`, and the pixel LSB carrier is detectable with standard steganalysis.
- Payloads are removed by any re-encoding of the image, including thumbnailing and platform
  transcoding. A lossless channel is required.
- The pixel LSB carrier requires a lossless output format and is bounded by the image dimensions.
- The automatic-entry receive mode stores the password inside the container and therefore provides
  no confidentiality.
- A temporary file the size of the payload is written to the application cache during hiding and
  extraction. The cache partition must have sufficient free space.

### Dependencies

- Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`) for AES, ChaCha20, SM4, PBKDF2 and SHA-256
- Material Components for Android and AndroidX for the user interface
- Material Icons (Apache License 2.0) for the interface icons

### License

Apache License 2.0 with an additional non-commercial condition — see `LICENSE` and `NOTICE`.

---

## 中文

### 项目简介

StegoBox 是一个 Android 应用，可以把任意数据（文件、压缩包或纯文本）嵌入图片中，并使用可认证
的加密保护载荷。

本项目不做夸大表述：它不宣称"无法被检测"，也不宣称载荷能在图片被重新处理后存活。下文的
"局限性"一节准确说明了它能做什么、不能做什么。

### 载体

StegoBox 提供两种载体，特性差异很大：

| 载体 | 载荷位置 | 容量 | 抗重编码 |
|---|---|---|---|
| 尾部追加 | 追加在图片字节之后 | 无上限，仅受文件大小限制 | 否 |
| 像素 LSB | R/G/B 三个通道的最低有效位 | `宽 × 高 × 3 / 8` 字节 | 否 |

两种载体都不具备抗图片处理能力：任何重新编码、缩略图生成或平台转码都会清除载荷。因此载荷
只适用于无损通道（直接文件传输、存储、局域网）。

### 密码学

所有密码学原语由 Bouncy Castle 的轻量级 API 提供，不注册 JCE provider，从而避免与 Android
内置的实现冲突。

- 算法：AES-256-GCM、ChaCha20-Poly1305、SM4-GCM，或不加密
- 密钥派生：PBKDF2-HMAC-SHA256，20 万次迭代，随机 16 字节盐
- 随机数：每个容器随机 12 字节 nonce
- 完整性：除 AEAD 认证标签外，另对明文计算 SHA-256

### 密钥模式与接收模式

密钥模式决定口令的来源：

| 密钥模式 | 行为 |
|---|---|
| 手写口令 | 由用户输入口令，接收方需要再次输入 |
| 随机口令 | 应用生成 16 位口令，可显示或复制 |
| 无口令 | 不加密，仅保留 SHA-256 完整性校验 |

接收模式决定接收方如何获得口令：

| 接收模式 | 行为 |
|---|---|
| 手动输入 | 容器使用口令加密，接收方必须输入口令 |
| 自动输入 | 口令保存在容器内，接收方无需输入；但容器不具备机密性，任何持有文件的人都能解密 |

### 容器格式（版本 3）

```
magic        5 字节   "SGBX3"
version      1 字节
carrier      1 字节   0 = 尾部追加，1 = 像素 LSB
cipher       1 字节   0 = 不加密，1 = AES-GCM，2 = ChaCha20-Poly1305，3 = SM4-GCM
keyMode      1 字节   0 = 无，1 = 口令，2 = 随文件保存
iterations   4 字节   大端
salt        16 字节
nonce       12 字节
payloadLen   8 字节   大端，存储载荷长度（密文 + 认证标签）
sha256      32 字节   明文的摘要
nameLen      2 字节   大端
name         n 字节   UTF-8；载荷为多文件包时为空
passwordLen  2 字节   仅当 keyMode 为"随文件保存"时存在
password     n 字节
payload      payloadLen 字节
```

### 功能

- 载荷一律按字节流处理：文档、图片、压缩包、应用均可
- 多文件自动打包为 ZIP，并自动处理重名条目
- 还原时，单文件保留原文件名，多文件保留原目录结构
- 载荷通过临时文件以流式方式处理，隐藏或提取数百 MB 的文件不会耗尽内存
- 像素 LSB 输出会经过卡方检验，并在日志中给出可检测性评估，如实告知嵌入的可见程度
- 输出可写入指定目录；授予"所有文件"权限后可直接写入 `Download/StegoBox`
- 内置自检界面，覆盖全部算法与密钥模式，以及两种载体

### 编译

需要 JDK 17、Android SDK（platform 35 及对应的 build tools），以及仓库内置的 Gradle Wrapper
（Gradle 8.9、Android Gradle Plugin 8.7.3）。

```
./gradlew :app:assembleRelease
```

发布签名请在 `app/build.gradle` 中配置为你自己的 keystore。

受限环境提示：在缺少兼容加载器的容器中，Android Gradle Plugin 自带的 `aapt2` 可能无法启动。
此时可将构建指向可用的二进制文件，例如：

```
android.aapt2FromMavenOverride=/usr/bin/aapt2
```

### 局限性

- 容器不具备隐蔽性。魔数与载荷用十六进制编辑器或 `strings` 即可看到，像素 LSB 载体可被常规
 隐写分析检出。
- 图片一旦被重新编码（包括生成缩略图、平台转码），载荷即被清除；必须使用无损通道。
- 像素 LSB 载体要求无损输出格式，且容量受图片尺寸限制。
- "自动输入"接收模式把口令保存在容器内，不具备机密性。
- 隐藏与提取过程中会在应用缓存目录写入与载荷等大的临时文件，请确保缓存分区有足够空间。

### 依赖

- Bouncy Castle（`org.bouncycastle:bcprov-jdk18on`）：AES、ChaCha20、SM4、PBKDF2、SHA-256
- Material Components for Android 与 AndroidX：界面
- Material Icons（Apache License 2.0）：界面图标

### 许可证

Apache License 2.0，附加非商业使用条件 —— 见 `LICENSE` 与 `NOTICE`。