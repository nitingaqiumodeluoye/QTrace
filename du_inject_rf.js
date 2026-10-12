// du_qtrace_inject.js — rustFrida 注入 QTrace 到得物
//   用法: rfclient -H 127.0.0.1:15819 spawn com.shizhuang.duapp -l du_qtrace_inject.js
//   QTrace libnativelib.so 加载后构造函数自动: 扫匿名区 → hook sg.ra → 首调 QBDI trace
var QTRACE = "/data/local/tmp/libnativelib.so";

// 等匿名区出现 (VM 解包后) 再注入 — 立即注入也行 (QTrace 内部有 2s 轮询重试)
// 简单策略: spawn 后延迟靠 QTrace 自己轮询, 直接加载
try {
    var m = Module.load(QTRACE);
    console.log("[inject] QTrace loaded: " + m.name + " base=" + m.base);
} catch (e) {
    console.log("[inject] load 失败: " + e);
}
