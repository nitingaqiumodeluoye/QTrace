# TrustAttestor ADB / 设备环境定向追踪

当前配置针对 TrustAttestor v1.2 (versionCode 12) 的 arm64 库：

- 模块：`libTrustAttestor.so`
- 目标函数 ELF 地址：`0x7097A8`，设备环境检查大函数（含 ADB 属性读取）
- 插桩范围：`[0x7097A8, 0x742B40)`，来自 `.eh_frame` 函数边界
- 直接调用链：`nativeRun 0x1A73C0 -> 0x1A92C0 -> 0x1EF4BC -> 0x7097A8`
- 不假定此函数返回值就是检测 mask，也不将它的参数误标成 JNI nativeRun 参数
- 目标 SO SHA-256：`4ecee29c9b1733a58735c39b010489f5ab2fac3ac2401851698482479d04918b`

运行时地址按 `dl_iterate_phdr` 返回的 `dlpi_addr + 0x7097A8` 计算，不能使用 executable maps 起点代替 load bias。

安装 hook 前会核对入口 16 字节（`fd 7b ba a9 fc 6f 01 a9 fa 67 02 a9 f8 5f 03 a9`）；不匹配则输出错误并停止安装，不能直接套用于其他版本。该检查只验证入口，不替代整个 SO 的哈希校验。旧 libtiny 的自定义偏移 hook 已禁用。

## CI 产物

GitHub Actions 工作流 `Build TrustAttestor QTrace` 使用 NDK `27.2.12479018`、CMake `3.22.1`，直接构建 `nativelib` 的 CMake 工程，目标 Android API 24 / arm64-v8a。无需本地运行 Gradle。

`qtrace-trustattestor-arm64` 包含：

- `libnativelib.so`：静态链接 C++ runtime 的 QTrace 库
- `inject.js`：Frida 17 注入脚本，等待 `libTrustAttestor.so` 加载；也支持模块已加载后的 attach
- `SHA256SUMS`、`build-info.txt`、`elf-info.txt`

CI 验证编译、链接、ARM64 架构和 JavaScript 语法。新目标的真机注入和 trace 仍需设备验证。

## 使用

将 CI 产物上传到设备，保留应用原版 SO：

```bash
adb push libnativelib.so /data/local/tmp/libnativelib.so
adb shell su -c 'chmod 755 /data/local/tmp/libnativelib.so'
frida -U -f com.lingqing.trustattestor -l inject.js
```

在 Git Bash 里，含 Android 绝对路径的 adb 命令前加 `MSYS_NO_PATHCONV=1`。Frida 路径需要已运行的 Frida 服务。目标定位使用动态链接器提供的 ELF 信息，不需要上传原版 SO 到 `/data/local/tmp/`；自定义加载器的匿名映射不在此加载回调的支持范围内。

### xfinject 早期注入

QTrace 构造函数对 linker 的 `__loader_dlopen` / `__loader_android_dlopen_ext` 安装地址 hook，保留原始 caller 参数，并检查已经加载的模块。原加载函数成功返回后检查目标库，再初始化追踪、校验入口并安装 hook。重复通知不会重复安装。不会捕获目标 ELF 构造函数内部已经执行的目标调用，也不支持目标卸载后重新加载。

项目自带 ShadowHook 2.0.0 静态库的 `shadowhook_init()` 未调用 `sh_linker_init()`；因此 dl-init 回调即使注册成功也不会工作，不能仅凭头文件存在该 API 使用它。

设备端 root 脚本内容：

```sh
#!/system/bin/sh
/data/local/tmp/karinaInject \
  -pkg com.lingqing.trustattestor \
  -lib /data/local/tmp/libnativelib.so \
  -debug -log-file /data/local/tmp/xfinject-qtrace.log
```

使用默认 UID 选择：设备上观察到主进程 cmdline 被改为探针服务名称，`-process-name` 精确过滤可能误拒主进程。JNI 表在注入构造阶段获取，防止载荷被 xfinject 摘链后 `dlsym(RTLD_DEFAULT, ...)` 失败。trace 写入应用内部存储，导出需要 root。

使用 `adb shell su -c "sh /data/local/tmp/run-qtrace.sh"` 执行该脚本（Git Bash 加 `MSYS_NO_PATHCONV=1`）。无需同时运行 `inject.js`。预期 QTrace logcat 先出现 `waiting for libTrustAttestor.so load (linker entry hooks)`，目标加载后出现 `environment probe hook installed`。CI 仅验证构建，真机效果仍需确认。

看到 QTrace 输出 `environment probe: load_bias=..., ELF=0x7097a8, entry=...` 后，在应用内触发扫描。日志输出到 `/data/user/0/com.lingqing.trustattestor/files/trace_logs/qbdi_*` 文件，完整路径由 logcat 输出。attach 模式只捕获安装 hook 后的调用；已经结束的扫描需要重新触发。

## 日志边界

- 不再追踪整个 nativeRun，也不自动将目标函数之外的子函数纳入逐指令插桩。
- 每个进程只尝试记录第一次目标调用；之后走原函数。首次初始化失败也会消耗该次机会，重试需重启进程。
- 最多记录 250,000 条指令，或约 64 MiB 日志，以先到者为准。字节阈值在完整指令记录后检查，允许超出最后一条记录及少量标记的大小，不是硬截断字节数。
- 每 1 MiB 刷盘；到达阈值立即写入 `RECORDING_LIMIT` 标记并刷盘，后续不再记录指令或内存访问，但目标继续在 QBDI 中执行。不通过 STOP 或重新执行目标来实现限额，仍可能存在插桩开销。
- 目标返回时输出 `target_return`、`recorded_instructions`、`truncated`、`qbdi_success`。`truncated=true` 只说明日志被截断，不代表目标调用被中断。若目标未返回或进程退出，不保证存在尾标记。
- 保留 GumTrace / trace-ui 指令格式及现有 JNI、libc 参数注解；此版本没有新增属性返回缓冲区快照或 `0x1FBA9C` 的 mask 采样。
