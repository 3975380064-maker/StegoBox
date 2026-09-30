## StegoBox 1.0.2

Hide files inside an image, protected by authenticated encryption.

### Changes in this release

- **Streaming I/O for the tail-append carrier.** Hiding and extracting no longer
  load the payload into memory. Data is staged in a temporary file and processed
  in 64 KiB chunks, so hiding or extracting several hundred megabytes works on a
  normal phone. Verified with a 352 MB payload on device and with a 50 MB payload
  under a 64 MB heap in an off-device test.
- **Steganalysis self-check.** When the pixel LSB carrier is used, the operation
  reports a detectability estimate based on the chi-square attack (Westfeld and
  Pfitzmann) together with the LSB-plane entropy, and flags the known false
  positive for flat images. Tail append is reported as not applicable and the
  reason is stated.
- **Built-in gallery picker.** Image selection uses an in-application thumbnail
  grid with multi-select instead of the system picker, which on Android 12
  devices without the system photo picker either opens the document manager or
  allows only a single selection.
- **Container header refactor.** The header writer and reader are shared between
  the in-memory and streaming paths, so both produce byte-identical files and
  files written by earlier versions remain readable.
- Fixed: cancelling a save dialog no longer leaves the interface disabled.
- Fixed: write failures are reported instead of being reported as success.
- Fixed: duplicate ZIP entry names no longer abort packing.

### Install

Download the APK below and install it. `minSdkVersion` 24, `targetSdkVersion` 35,
package name `com.stegolab.stegobox`, signed release build.

### SHA-256

```
__SHA256__
```

---

## StegoBox 1.0.2（中文说明）

把文件藏进图片，并使用可认证的加密保护。

### 本次更新

- **尾部追加载体改为流式处理。** 隐藏与提取都不再把载荷整体读入内存，数据先落到
 临时文件，按 64 KiB 分块处理，因此在普通手机上隐藏或提取几百 MB 是可行的。
  已在设备上以 352 MB 载荷验证，并在离线测试中以 64 MB 堆处理 50 MB 载荷通过。
- **隐写分析自检。** 使用像素 LSB 时，会给出基于卡方攻击（Westfeld、Pfitzmann）
  的可检测性估计与 LSB 平面熵，并提示纯色平坦图像的已知误报情形。尾部追加会提示
  该项不适用，并说明原因。
- **内置相册选择器。** 选图改用应用内的缩略图网格，支持多选，不再依赖系统选择器。
  在未内置系统照片选择器的 Android 12 设备上，系统路径要么打开文件管理器，要么
  只能单选一张。
- **容器头部重构。** 头部读写由内存路径与流式路径共用，两者生成的字节完全一致，
  旧版本写出的文件仍可读取。
- 修复：取消保存对话框后界面不再保持禁用状态。
- 修复：写入失败会如实报错，不再误报为成功。
- 修复：ZIP 条目重名不再导致打包失败。

### 安装

下载下方 APK 安装。`minSdkVersion` 24、`targetSdkVersion` 35，包名
`com.stegolab.stegobox`，release 已签名。

### 作者与项目地址

- 作者：喵喵喵（GitHub：3975380064-maker）
- 项目地址：https://github.com/3975380064-maker/StegoBox