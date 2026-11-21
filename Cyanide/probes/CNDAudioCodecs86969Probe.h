#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Benign reachability trace. Plays Apple's public, valid E-AC-3 HLS sample
// through AVPlayer and samples the IOAudioCodecs registry subtree before,
// during, and after playback. This path does not acquire KRW, open the
// IOAudioCodecs user client directly, or submit attacker-shaped packet data.
void CNDAudioCodecs86969PlaybackTraceRun(
    void (^completion)(NSDictionary<NSString *, id> *report));

// CVE-2026-86969 probe: drives the genuine IOAudioCodecs user client path.
//
// benign=NO is the destructive, exact-target-gated raw trigger. It initializes
// the private 'cac3' header format, maps memory type 0 for the codec input,
// runs sync-word-valid controls, then submits selector 5 with inSize 7..0.
// On vulnerable 24A446 the first raw call is expected to panic in
// A5AC3PassThrough::ProcessSinglePacket. The last pre-call record is persisted
// to Documents/a86969-raw-attempt.json because a panic cannot return a report.
//
// benign=YES runs only a sync-word-valid control. Neither mode acquires KRW.
void CNDAudioCodecs86969ProbeRun(
    BOOL benign,
    void (^completion)(NSDictionary<NSString *, id> *report));

// KRW-assisted variant (physical 23A341). Uses the app's kexploit KRW
// (kreadbuf/kwrite64, g_kernel_base) only to:
//   (a) live-verify the statically resolved IOAudioCodecs statics
//       (dispatch table, instance vtable, codec vtable slot 8), and
//   (b) temporarily copy launchd's PAC-signed cr_label (raw 64-bit copy, so
//       the PAC bits stay valid) into our own ucred so the MACF/sandbox
//       user-client check lets IOServiceOpen through.
// The label is restored before the completion fires. After the open, the
// trigger goes through the genuine IOConnectCallMethod path (sel 2 init,
// sel 5 packet) - the memory corruption, if any, is the CVE's, not KRW's.
void CNDAudioCodecs86969KrwProbeRun(
    BOOL benign,
    void (^completion)(NSDictionary<NSString *, id> *report));

NS_ASSUME_NONNULL_END
