"use strict";

// Frida 17.15+ injection script for QTrace.
const TARGET_MODULE = "libTrustAttestor.so";
const QTRACE_PATH = "/data/local/tmp/libnativelib.so";
const RTLD_NOW = 2;

let injectionStarted = false;
let injectionSucceeded = false;
const loaderListeners = [];

function log(message) {
  console.log("[QTrace] " + message);
}

function fail(message) {
  console.error("[QTrace] " + message);
}

function findGlobalExport(symbolName) {
  const address = Module.findGlobalExportByName(symbolName);
  if (address === null) {
    log("global export not found: " + symbolName);
  }
  return address;
}

function readLibraryPath(address) {
  if (address === null || address.isNull()) {
    return null;
  }

  try {
    return address.readCString();
  } catch (error) {
    log("unable to read loader path: " + error);
    return null;
  }
}

function isTargetLibrary(path) {
  if (path === null) {
    return false;
  }
  return path === TARGET_MODULE || path.endsWith("/" + TARGET_MODULE);
}

function injectQTrace(reason) {
  if (injectionSucceeded || injectionStarted) {
    return injectionSucceeded;
  }

  injectionStarted = true;
  try {
    const dlopenAddress = Module.getGlobalExportByName("dlopen");
    const dlopen = new NativeFunction(
      dlopenAddress,
      "pointer",
      ["pointer", "int"]
    );
    const path = Memory.allocUtf8String(QTRACE_PATH);
    const handle = dlopen(path, RTLD_NOW);

    if (handle.isNull()) {
      let detail = "unknown dlopen error";
      const dlerrorAddress = Module.findGlobalExportByName("dlerror");
      if (dlerrorAddress !== null) {
        const dlerror = new NativeFunction(dlerrorAddress, "pointer", []);
        const errorPointer = dlerror();
        if (!errorPointer.isNull()) {
          detail = errorPointer.readCString();
        }
      }
      throw new Error(detail);
    }

    injectionSucceeded = true;
    log("loaded " + QTRACE_PATH + " after " + reason + ", handle=" + handle);
    return true;
  } catch (error) {
    fail("injection failed after " + reason + ": " + error);
    return false;
  } finally {
    injectionStarted = false;
  }
}

function installLoaderHook(symbolName) {
  const address = findGlobalExport(symbolName);
  if (address === null) {
    return false;
  }

  const listener = Interceptor.attach(address, {
    onEnter(args) {
      this.targetPath = readLibraryPath(args[0]);
      this.isTarget = isTargetLibrary(this.targetPath);
    },

    onLeave(retval) {
      if (!this.isTarget) {
        return;
      }
      if (retval.isNull()) {
        fail(symbolName + " failed to load " + this.targetPath);
        return;
      }
      injectQTrace(symbolName + "(" + this.targetPath + ")");
    }
  });

  loaderListeners.push(listener);
  log("hooked " + symbolName + " at " + address);
  return true;
}

function main() {
  log("Frida " + Frida.version + ", waiting for " + TARGET_MODULE);

  const loaded = Process.findModuleByName(TARGET_MODULE);
  if (loaded !== null) {
    log(TARGET_MODULE + " is already loaded at " + loaded.base);
    injectQTrace("existing module");
    return;
  }

  let hookCount = 0;
  if (installLoaderHook("__loader_dlopen")) {
    hookCount += 1;
  }
  if (installLoaderHook("android_dlopen_ext")) {
    hookCount += 1;
  }
  if (hookCount === 0 && installLoaderHook("dlopen")) {
    hookCount += 1;
  }

  if (hookCount === 0) {
    throw new Error("no supported loader export was found");
  }
}

setImmediate(function () {
  try {
    main();
  } catch (error) {
    fail("fatal error: " + error + (error.stack ? "\n" + error.stack : ""));
  }
});
