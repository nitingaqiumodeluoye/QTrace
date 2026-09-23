# TrustAttestor nativeRun 追踪

当前配置针对 TrustAttestor v1.2 (versionCode 12) 的 arm64 库：

- 模块：`libTrustAttestor.so`
- Java 方法：`com.lingqing.trustattestor.TrustAttestorNativeBridge.nativeRun`
- JNI 签名：`(Landroid/content/Context;Lcom/lingqing/trustattestor/NativeScanCallback;)V`
- JNI 入口 ELF 地址：`0x1A73C0`，入口参数为 `JNIEnv*, jclass, Context, NativeScanCallback`
- 入口指令：`mov x1, x2; mov x2, x3; b 0x1A92C0`
- 目标 SO SHA-256：`4ecee29c9b1733a58735c39b010489f5ab2fac3ac2401851698482479d04918b`

运行时地址按 `dl_iterate_phdr` 返回的 `dlpi_addr + 0x1A73C0` 计算。历史 trace 的 load bias 是 `0x70BA403000`，运行时入口是 `0x70BA5AA3C0`。`0x1AA3C0` 是曾经使用错误基址得到的值，不应作为 ELF 地址使用。

安装 hook 前会核对入口 12 字节；不匹配则输出错误并停止安装，不能直接套用于其他版本。该检查只验证入口，不替代整个 SO 的哈希校验。旧 libtiny 的自定义偏移 hook 已禁用。

## CI 产物

GitHub Actions 工作流 `Build TrustAttestor QTrace` 使用 NDK `27.2.12479018`、CMake `3.22.1`，直接构建 `nativelib` 的 CMake 工程，目标 Android API 24 / arm64-v8a。无需本地运行 Gradle。

`qtrace-trustattestor-arm64` 包含：

- `libnativelib.so`：静态链接 C++ runtime 的 QTrace 库
- `inject.js`：Frida 17 注入脚本，等待 `libTrustAttestor.so` 加载；也支持模块已加载后的 attach
- `SHA256SUMS`、`build-info.txt`、`elf-info.txt`

CI 验证编译、链接、ARM64 架构和 JavaScript 语法。真机注入和 nativeRun trace 仍需设备验证。

## 使用

将 CI 产物上传到设备，保留应用原版 SO：

```bash
adb push libnativelib.so /data/local/tmp/libnativelib.so
adb shell su -c 'chmod 755 /data/local/tmp/libnativelib.so'
frida -U -f com.lingqing.trustattestor -l inject.js
```

在 Git Bash 里，含 Android 绝对路径的 adb 命令前加 `MSYS_NO_PATHCONV=1`。需要已运行的 Frida 服务和允许注入的设备环境。若库由匿名映射等方式加载，路径回退定位需要将同版 `libTrustAttestor.so` 放到 `/data/local/tmp/`。

看到 QTrace 输出 `TrustAttestorNativeBridge.nativeRun: load_bias=..., ELF=0x1a73c0, entry=...` 后，在应用内触发扫描。日志输出到应用私有目录的 `trace_logs/qbdi_*` 文件，完整路径由 logcat 输出。attach 模式只捕获安装 hook 后的调用；已经结束的扫描需要重新触发。

此目标覆盖整个 nativeRun，不仅是 L2。日志保留现有 GumTrace / trace-ui 格式及 JNI、libc 参数注解。
