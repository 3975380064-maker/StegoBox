# StegoBox

**Hide any file inside an image — with real authenticated encryption.**
**把任意文件藏进一张图片里 —— 带真正可认证的加密。**

> ⚠️ **License: CC BY-NC-SA 4.0 — NON-COMMERCIAL USE ONLY.**
> **协议：CC BY-NC-SA 4.0 —— 仅限非商业用途，禁止商用。** See [LICENSE](LICENSE).

---

## English

### What it is

An Android app that packs arbitrary data (files, images, archives, plain text) into an image.
Unlike the many "hide files in a picture" toys, the payload here is **encrypted and integrity-checked**,
so even if someone extracts it, they get ciphertext — not your data.

**This is an honest tool.** It does **not** claim to be undetectable; see [Limitations](#limitations).

### Carriers

| Carrier | Capacity | Survives re-encode? |
|---|---|---|
| **Tail-append** — the envelope is appended after the image bytes | unlimited (the file simply grows) | ❌ no |
| **Pixel LSB** — 1 bit per R/G/B byte, outputs PNG | `W × H × 3 / 8` bytes | ❌ no |

### Cryptography

Implemented with **Bouncy Castle's lightweight API** (no JCE provider is registered, so it cannot
clash with Android's built-in BC provider):

- **Ciphers:** `AES-256-GCM`, `ChaCha20-Poly1305`, `SM4-GCM` (国密), or *no encryption*
- **Key derivation:** PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt
- **Nonce:** random 12 bytes per envelope
- **Integrity:** SHA-256 of the plaintext **plus** the AEAD tag (verify-then-use)

### Key modes

| 密钥模式 | Behaviour |
|---|---|
| 手写口令 | you type the password; the receiver must type it too |
| 随机口令 | the app generates a 16-char password, shown and copyable |
| 无口令 | no password → encryption is disabled (plaintext + SHA-256 only) |

**Receive mode**

| 接收模式 | Behaviour |
|---|---|
| 手动输入 | envelope is encrypted with the password; receiver must enter it |
| 自动输入（图片输入） | the password is **stored inside the file**, so the receiver needs no input — ⚠️ **this provides no confidentiality at all**, anyone with the file can decrypt it |

### Container format (v3)

```
magic(5 "SGBX3") ver(1) carrier(1) cipher(1) keyMode(1) iters(4 BE)
salt(16) nonce(12) payloadLen(8 BE) sha256(32)
nameLen(2 BE) + nameUTF8        (0 => multi-file bundle/ZIP)
[if keyMode == EMBEDDED: pwLen(2) + password]
payload (= ciphertext||tag, or plaintext when unencrypted)
```

### Features

- Any payload: files, images, APKs, archives, or typed text — treated as raw bytes
- **Multiple items at once** → packed into a ZIP with **de-duplicated** entry names
- **Faithful restore**: single file keeps its original name; bundles are restored with their directory structure
- **Fixed output directory** (SAF) or **direct write to `Download/StegoBox`** when "All files access" is granted
- Built-in **self-test** button that round-trips every cipher × key mode, verifies tail-append and LSB

### Build

```bash
# JDK 17, Android SDK (platform 35 + build-tools), Gradle 8.9 (wrapper included), AGP 8.7.3
./gradlew :app:assembleRelease
```

Signing: create your own keystore and point `signingConfigs.release` in `app/build.gradle` at it.

> **Container note:** in some restricted/proot environments the `aapt2` bundled with AGP cannot
> start. Workaround (already present in `gradle.properties`):
> `android.aapt2FromMavenOverride=/usr/bin/aapt2`

### Limitations

- **Not stealthy.** The `SGBX3` magic and the payload are plainly visible with `strings`; pixel LSB is
  detectable by standard steganalysis. Assume a competent adversary detects it.
- **Tail-append data is destroyed** by any re-encode / thumbnail / platform transcode — use a lossless channel.
- **Pixel LSB** needs PNG and also dies on re-encode; capacity is strictly `W×H×3/8` bytes.
- **"自动输入" mode stores the password in the file** — convenience only, zero security.
- Whole-file operations are in-memory; very large selections can be memory-hungry.

### Credits

- [Bouncy Castle](https://www.bouncycastle.org/) for AES / ChaCha20 / SM4 / PBKDF2 / SHA-256
- [Material Icons](https://github.com/google/material-design-icons) (Apache-2.0) for the UI icons

---

## 中文

### 这是什么

一个把任意数据（文件、图片、压缩包、纯文本）打包进图片的 Android 应用。
和那些"把文件塞进图片"的玩具不同，这里的载荷是**加密且带完整性校验**的——
即使被别人提取出来，拿到的也只是密文。

**这是一个诚实的工具**：它**不**宣称"无法被检测"，见 [局限性](#局限性)。

### 载体方式

| 载体 | 容量 | 抗重编码？ |
|---|---|---|
| **尾部追加**：把信封数据追加在图片字节之后 | **无上限**（文件会变大而已） | ❌ 不行 |
| **像素 LSB**：每个 R/G/B 字节嵌 1 位，输出 PNG | `宽 × 高 × 3 / 8` 字节 | ❌ 不行 |

### 密码学

基于 **Bouncy Castle 轻量级 API**（不注册 JCE provider，因此不会与 Android 内置 BC 冲突）：

- **算法**：`AES-256-GCM`、`ChaCha20-Poly1305`、`SM4-GCM`（国密），或**不加密**
- **密钥派生**：PBKDF2-HMAC-SHA256，20 万次迭代，随机 16 字节盐
- **随机数**：每个信封随机 12 字节 nonce
- **完整性**：明文 SHA-256 **加上** AEAD 认证标签（先验签再用）

### 密钥模式与接收模式

| 密钥模式 | 行为 |
|---|---|
| 手写口令 | 你自己输入口令，接收方也需要输入 |
| 随机口令 | App 生成 16 位口令，可直接显示/复制 |
| 无口令 | 无口令 → 自动改为不加密（仅明文 + SHA-256 校验） |

| 接收模式 | 行为 |
|---|---|
| 手动输入 | 口令加密，接收方需输入口令 |
| 自动输入（图片输入） | 口令**随文件保存**，接收方无需输入 —— ⚠️ **完全不具备机密性**，任何拿到文件的人都能解开 |

### 容器格式（v3）

```
magic(5 字节 "SGBX3") ver(1) carrier(1) cipher(1) keyMode(1) iters(4 大端)
salt(16) nonce(12) payloadLen(8 大端) sha256(32)
nameLen(2 大端) + 文件名(UTF-8)     （0 表示多文件包/ZIP）
[若为「自动输入」：pwLen(2) + 口令]
payload（= 密文||标签；不加密时即明文）
```

### 功能

- 载荷任意：文件、图片、APK、压缩包，或直接输入文本 —— 一律按字节流处理
- **可一次藏多个**：自动打成 ZIP，并**自动去重**条目名（避免 ZIP 重名报错）
- **忠实还原**：单文件还原成原名；多文件按**原目录结构**还原
- **固定输出目录**（SAF）或授权"所有文件权限"后**直写 `Download/StegoBox`**（不再弹框）
- 内置**自检**按钮：遍历所有算法 × 密钥模式做往返验证，并校验尾部追加与像素 LSB

### 编译

```bash
# 需要 JDK 17、Android SDK（platform 35 + build-tools）、Gradle 8.9（已含 wrapper）、AGP 8.7.3
./gradlew :app:assembleRelease
```

签名：请自建 keystore，并修改 `app/build.gradle` 中的 `signingConfigs.release`。

> **环境提示**：在某些受限/proot 环境里，AGP 自带的 `aapt2` 无法启动。
> 绕过方式（`gradle.properties` 里已带）：
> `android.aapt2FromMavenOverride=/usr/bin/aapt2`

### 局限性（必读）

- **不隐蔽**。`SGBX3` 魔数和载荷用 `strings` 就能看出来；像素 LSB 也会被常规隐写分析检出。请假设有能力的对手能发现它。
- **尾部追加的数据**会被任何重编码 / 缩略图 / 平台转码**直接抹掉** —— 请走无损通道。
- **像素 LSB** 需要 PNG，同样扛不住重编码；容量严格等于 `宽×高×3/8` 字节。
- **「自动输入」模式把口令存在文件里** —— 只图方便，安全性为零。
- 整个载荷在内存中处理，一次选择过多/过大的文件会比较吃内存。

### 致谢

- [Bouncy Castle](https://www.bouncycastle.org/)：AES / ChaCha20 / SM4 / PBKDF2 / SHA-256
- [Material Icons](https://github.com/google/material-design-icons)（Apache-2.0）：界面图标

---

## License / 协议

**Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)**

- ✅ 允许：个人使用、学习研究、非商业分发（需署名并以相同方式共享）
- ❌ **禁止：任何商业用途**（包括售卖、付费服务、商业产品内置等）

完整条款见 [LICENSE](LICENSE)。商业授权请联系作者。
