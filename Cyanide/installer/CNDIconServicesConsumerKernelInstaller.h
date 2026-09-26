#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// VM/legacy non-PAC installer for the marker-aware IconRendering payload.
/// The target receives one raw bootstrap thread, creates one ordinary pthread
/// to perform the Objective-C runtime work, then the bootstrap and task-control
/// channel are destroyed. Physical arm64e is routed through the signed-vnode
/// RemoteCall installer instead.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerKernelInstallForProcess(NSString *processName,
                                                double displayScale);

/// PID-bound entry point for the Phase-3 process lifecycle watcher.
NSDictionary<NSString *, id> *
CNDIconServicesConsumerKernelInstallForPID(pid_t pid,
                                            NSString *expectedProcessName,
                                            double displayScale);

NS_ASSUME_NONNULL_END
