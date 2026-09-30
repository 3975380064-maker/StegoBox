# StegoBox

Hide files inside an image, protected by authenticated encryption.

StegoBox is an Android application that embeds arbitrary data (files, images,
archives or plain text) into an image and extracts it again. The payload is
encrypted with an AEAD cipher and verified with SHA-256, so the extracted bytes
are unreadable without the password and any modification is detected.

- Author: 喵喵喵 (GitHub: [3975380064-maker](https://github.com/3975380064-maker))
- Repository: <https://github.com/3975380064-maker/StegoBox>
- License: Apache-2.0 with an additional non-commercial condition, see
  [NOTICE](NOTICE) and [LICENSE](LICENSE).

## Download

Download `StegoBox-<version>-release.apk` from the
[Releases](https://github.com/3975380064-maker/StegoBox/releases) page and install
it. Android will ask you to allow installation from unknown sources the first time.

- `minSdkVersion` 24, `targetSdkVersion` 35
- Package name: `com.stegolab.stegobox`

After installation, open the "Output" section and grant the storage permission.
With that permission the application writes directly to `Download/StegoBox` and
does not show a save dialog for every operation.

## Carriers

Two embedding methods are available.

| Carrier | Capacity | Survives re-encoding |
| --- | --- | --- |
| Tail append | Unlimited; the image file simply grows | No |
| Pixel LSB | `width * height * 3 / 8` bytes, PNG output | No |

The **tail append** carrier writes the container after the image data. Any
re-encode, thumbnail or platform transcode removes it, so it requires a lossless
channel. The **pixel LSB** carrier modifies one bit per R/G/B byte and therefore
needs a lossless format as well.

## Cryptography

Implemented with the Bouncy Castle lightweight API. No JCE provider is
registered, so it does not conflict with the provider bundled with Android.

- Ciphers: AES-256-GCM, ChaCha20-Poly1305, SM4-GCM, or no encryption
- Key derivation: PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt
- Nonce: random 12 bytes per container
- Integrity: SHA-256 over the plaintext in addition to the AEAD tag

## Key modes and receive modes

| Key mode | Behaviour |
| --- | --- |
| Manual password | The password is entered by the user |
| Random password | The application generates a 16 character password, which can be displayed and copied |
| No password | No password, encryption is disabled; only SHA-256 integrity remains |

| Receive mode | Behaviour |
| --- | --- |
| Manual input | The payload is encrypted with the password; the receiver enters it |
| Automatic input | The password is stored inside the file so the receiver does not need to type it. This provides no confidentiality |

## Container format

Version 3 of the container is a fixed header followed by the payload:

```
magic (5 bytes, "SGBX3")  version (1)  carrier (1)  cipher (1)  keyMode (1)
iterations (4, big endian)  salt (16)  nonce (12)  payloadLength (8, big endian)
sha256 (32)
nameLength (2) + name (UTF-8; length 0 means the payload is a multi-file ZIP)
[if keyMode is EMBEDDED: passwordLength (2) + password]
payload (ciphertext with tag, or plaintext when encryption is disabled)
```

## Usage

1. Select the cover image.
2. Select the carrier, the cipher, the key mode and the receive mode.
3. Choose the content to hide: type text and/or select images and files. More
   than one item is packed into a ZIP archive; duplicate names are made unique
   automatically.
4. Select the output location, then start the operation.
5. To extract, select the resulting image with "Extract", enter the password if
   required, and choose where the files should be restored. Single files keep
   their original name; archives are restored with their directory structure.

Large payloads are processed in a streaming fashion: the data is staged in a
temporary file and never held in memory, so hiding or extracting several hundred
megabytes works on a normal phone. Note that both operations need temporary disk
space equal to the payload size.

## Steganalysis self-check

The **Self-test** button runs a round trip over every cipher and key mode and
verifies both carriers. When the pixel LSB carrier is used, hiding also reports a
detectability estimate based on the chi-square attack (Westfeld and Pfitzmann)
together with the entropy of the LSB plane. The padding used by the filter is
reported so that flat images, a known false positive of the test, can be
recognised. Tail append does not modify pixels, so the estimate is not meaningful
for that carrier; the payload is visible to a `strings` scan of the file instead.

## Building

Requirements: JDK 17, Android SDK with platform 35, Gradle 8.9 (wrapper
included), Android Gradle Plugin 8.7.3.

```
./gradlew :app:assembleRelease
```

Create your own keystore and point `signingConfigs.release` in
`app/build.gradle` at it.

Note: in restricted environments (for example inside a proot container) the
`aapt2` binary shipped with the Android Gradle Plugin may fail to start. The
workaround is present in `gradle.properties`:
`android.aapt2FromMavenOverride=/usr/bin/aapt2`.

## Limitations

- The container is not stealthy. The `SGBX3` marker and the payload can be seen
  with a hex editor or a `strings` scan, and pixel LSB embeddings are detectable
  with standard steganalysis.
- Tail append data is destroyed by any re-encoding of the image.
- Pixel LSB requires PNG and is also destroyed by re-encoding. Its capacity is
  strictly limited.
- The automatic input mode stores the password in the file and therefore offers
  no confidentiality.
- Pixel LSB operations decode the whole bitmap and are limited by the memory of
  the device; tail append is streamed and has no such limit.

## Acknowledgements

- [Bouncy Castle](https://www.bouncycastle.org/) for AES, ChaCha20, SM4, PBKDF2
  and SHA-256
- [Material Icons](https://github.com/google/material-design-icons) (Apache-2.0)
  for the user interface icons

---

## 中文说明

把文件藏进图片，并使用可认证的加密保护。

StegoBox 是一个 Android 应用，可以把任意数据（文件、图片、压缩包或纯文本）嵌入
一张图片，并可再次提取。载荷使用 AEAD 算法加密、使用 SHA-256 校验，因此没有口令
无法读取，任何改动都能被发现。

- 作者：喵喵喵（GitHub：[3975380064-maker](https://github.com/3975380064-maker)）
- 项目地址：<https://github.com/3975380064-maker/StegoBox>
- 协议：Apache-2.0 并附加禁止商用条款，见 [NOTICE](NOTICE) 与 [LICENSE](LICENSE)

### 下载与安装

在 [Releases](https://github.com/3975380064-maker/StegoBox/releases) 页面下载
`StegoBox-<版本>-release.apk` 安装。首次安装需要允许「未知来源」。

- `minSdkVersion` 24，`targetSdkVersion` 35
- 包名：`com.stegolab.stegobox`

安装后请到「输出」卡片授予存储权限。授权后应用直接写入 `Download/StegoBox`，
不会每次操作都弹出保存框。

### 载体方式

| 载体 | 容量 | 抗重编码 |
| --- | --- | --- |
| 尾部追加 | 无上限，图片文件会变大 | 不行 |
| 像素 LSB | `宽 * 高 * 3 / 8` 字节，输出 PNG | 不行 |

尾部追加把容器写在图片数据之后，任何重编码、缩略图或平台转码都会将其移除，
因此需要无损传输通道。像素 LSB 每个 R/G/B 字节修改一位，同样需要无损格式。

### 密码学

基于 Bouncy Castle 轻量级 API 实现。不注册 JCE provider，因此不会与 Android
内置的 provider 冲突。

- 算法：AES-256-GCM、ChaCha20-Poly1305、SM4-GCM，或不加密
- 密钥派生：PBKDF2-HMAC-SHA256，20 万次迭代，随机 16 字节盐
- 随机数：每个容器 12 字节随机 nonce
- 完整性：除 AEAD 标签外，另对明文计算 SHA-256

### 密钥模式与接收模式

| 密钥模式 | 行为 |
| --- | --- |
| 手写口令 | 口令由用户输入 |
| 随机口令 | 应用生成 16 位口令，可显示与复制 |
| 无口令 | 不使用口令，自动改为不加密，仅保留 SHA-256 校验 |

| 接收模式 | 行为 |
| --- | --- |
| 手动输入 | 载荷使用口令加密，接收方需要输入口令 |
| 自动输入 | 口令保存在文件内，接收方无需输入。此模式不具备机密性 |

### 容器格式

第 3 版容器由固定头部与载荷组成：

```
magic（5 字节 "SGBX3"）version（1）carrier（1）cipher（1）keyMode（1）
iterations（4，大端）salt（16）nonce（12）payloadLength（8，大端）sha256（32）
nameLength（2）+ 文件名（UTF-8；长度为 0 表示载荷是多文件 ZIP）
[若 keyMode 为 EMBEDDED：passwordLength（2）+ 口令]
载荷（含标签的密文；不加密时为明文）
```

### 使用方法

1. 选择封面图片。
2. 选择载体方式、加密算法、密钥模式与接收模式。
3. 选择要隐藏的内容：可以输入文本，也可以选择图片与文件。多于一项时会自动
 打包为 ZIP，重名的条目会自动改名。
4. 选择输出位置并开始隐藏。
5. 提取时用「解出」选择生成的图片，按需输入口令，并选择还原位置。单文件按原名
 还原，多文件按原目录结构还原。

大载荷采用流式处理：数据先落到临时文件，不会整体读入内存，因此在普通手机上
隐藏或提取几百 MB 也是可行的。注意隐藏与提取都需要等量的临时磁盘空间。

### 隐写分析自检

「自检」按钮会遍历所有算法与密钥模式做一次往返验证，并校验两种载体。使用
像素 LSB 时，隐藏完成后还会给出基于卡方攻击（Westfeld、Pfitzmann）的可检测性
估计，以及 LSB 平面熵。界面会提示该测试对纯色平坦图像的已知误报情形。尾部追加
不修改像素，因此该估计对其没有意义；这种情况下载荷内容用 `strings` 即可看到。

### 编译

需要 JDK 17、Android SDK（platform 35）、Gradle 8.9（已含 wrapper）、
Android Gradle Plugin 8.7.3。

```
./gradlew :app:assembleRelease
```

请自行创建 keystore，并把 `app/build.gradle` 中的 `signingConfigs.release`
指向它。

注意：在受限环境（例如 proot 容器）中，Android Gradle Plugin 自带的 `aapt2`
可能无法启动。绕过方式已写入 `gradle.properties`：
`android.aapt2FromMavenOverride=/usr/bin/aapt2`。

### 局限性

- 容器不隐蔽。`SGBX3` 标记与载荷用十六进制编辑器或 `strings` 即可看到，像素 LSB
 也会被常规隐写分析检出。
- 图片一旦被重新编码，尾部追加的数据会失效。
- 像素 LSB 需要 PNG，同样无法承受重新编码；容量有严格上限。
- 自动输入模式把口令保存在文件里，不具备机密性。
- 像素 LSB 需要解码整张位图，受设备内存限制；尾部追加为流式处理，没有该限制。

### 致谢

- [Bouncy Castle](https://www.bouncycastle.org/)：AES、ChaCha20、SM4、PBKDF2、SHA-256
- [Material Icons](https://github.com/google/material-design-icons)（Apache-2.0）：界面图标
