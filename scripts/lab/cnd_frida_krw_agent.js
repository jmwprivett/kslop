'use strict';

/* Observation-only SpringBoard checkpoint for cnd_frida_krw_bridge.py. */

rpc.exports = {
  checkpoint(label) {
    const modules = Process.enumerateModules();
    const selectedNames = new Set([
      'SpringBoard',
      'UIKitCore',
      'FrontBoard',
      'FrontBoardServices',
      'libsystem_kernel.dylib',
      'libdispatch.dylib'
    ]);
    const selectedModules = modules
      .filter(module => selectedNames.has(module.name))
      .slice(0, 16)
      .map(module => ({
        name: module.name,
        path: module.path,
        base: module.base.toString(),
        size: module.size
      }));
    const main = Process.mainModule;
    return {
      schema: 'com.zeroxjf.cyanide.frida-krw-checkpoint',
      schemaVersion: 1,
      label,
      pid: Process.id,
      arch: Process.arch,
      platform: Process.platform,
      pointerSize: Process.pointerSize,
      moduleCount: modules.length,
      mainModule: {
        name: main.name,
        path: main.path,
        base: main.base.toString(),
        size: main.size
      },
      selectedModules
    };
  }
};
