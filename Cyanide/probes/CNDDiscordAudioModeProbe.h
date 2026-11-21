#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDDiscordAudioModeProbeCompletion)(
    NSDictionary<NSString *, id> *report);

BOOL CNDDiscordAudioModeProbeIsSupported(
    NSString * _Nullable * _Nullable reasonOut);
BOOL CNDDiscordAudioModeProbeIsRunning(void);
BOOL CNDDiscordAudioModeProbeHasRecoveryJournal(void);

/// Captures Discord's current mode and preferred input in a durable journal,
/// requests AVAudioSessionModeDefault, selects the built-in iPhone microphone,
/// and leaves that audio configuration active after the RemoteCall thread is
/// restored. A second apply refuses while the recovery journal is active.
void CNDDiscordAudioModeProbeApply(
    CNDDiscordAudioModeProbeCompletion completion);

/// Reopens the exact journaled Discord process, restores the captured mode and
/// preferred input, verifies both readbacks, and removes the recovery journal.
void CNDDiscordAudioModeProbeRestore(
    CNDDiscordAudioModeProbeCompletion completion);

NS_ASSUME_NONNULL_END
