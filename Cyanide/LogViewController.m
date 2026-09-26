//
//  LogViewController.m
//  Cyanide
//

#import "LogViewController.h"
#import "LogTextView.h"
#import <sys/utsname.h>

@interface LogViewController ()
@property (nonatomic, strong) UILabel *bannerLabel;
@property (nonatomic, strong) LogTextView *logView;
@end

@implementation LogViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"Log";

    UIImage *copyIcon = [UIImage systemImageNamed:@"doc.on.doc"];
    UIBarButtonItem *copyItem = nil;
    if (copyIcon) {
        copyItem = [[UIBarButtonItem alloc] initWithImage:copyIcon
                                                    style:UIBarButtonItemStylePlain
                                                   target:self
                                                   action:@selector(copyFullLog:)];
        copyItem.accessibilityLabel = @"Copy Log";
    } else {
        copyItem = [[UIBarButtonItem alloc] initWithTitle:@"Copy"
                                                    style:UIBarButtonItemStylePlain
                                                   target:self
                                                   action:@selector(copyFullLog:)];
    }

    UIImage *relevantIcon = [UIImage systemImageNamed:@"line.3.horizontal.decrease.circle"];
    UIBarButtonItem *relevantItem = nil;
    if (relevantIcon) {
        relevantItem = [[UIBarButtonItem alloc] initWithImage:relevantIcon
                                                        style:UIBarButtonItemStylePlain
                                                       target:self
                                                       action:@selector(copyRelevantLog:)];
        relevantItem.accessibilityLabel = @"Copy Relevant Log";
    } else {
        relevantItem = [[UIBarButtonItem alloc] initWithTitle:@"Relevant"
                                                        style:UIBarButtonItemStylePlain
                                                       target:self
                                                       action:@selector(copyRelevantLog:)];
    }
    self.navigationItem.rightBarButtonItems = @[ copyItem, relevantItem ];

    UIColor *bg = [UIColor colorWithRed:0.04 green:0.05 blue:0.07 alpha:1.0];
    self.view.backgroundColor = bg;

    _bannerLabel = [[UILabel alloc] init];
    _bannerLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _bannerLabel.numberOfLines = 0;
    _bannerLabel.font = [UIFont monospacedSystemFontOfSize:11.5 weight:UIFontWeightRegular];
    _bannerLabel.textColor = [UIColor colorWithWhite:0.86 alpha:1.0];
    _bannerLabel.backgroundColor = [UIColor colorWithRed:0.06 green:0.07 blue:0.10 alpha:1.0];
    _bannerLabel.textAlignment = NSTextAlignmentLeft;
    _bannerLabel.attributedText = [self buildBannerText];
    _bannerLabel.layer.cornerRadius = 10;
    _bannerLabel.clipsToBounds = YES;
    [self.view addSubview:_bannerLabel];

    UIView *separator = [[UIView alloc] init];
    separator.translatesAutoresizingMaskIntoConstraints = NO;
    separator.backgroundColor = [UIColor colorWithWhite:1.0 alpha:0.07];
    [self.view addSubview:separator];

    _logView = [[LogTextView alloc] initWithFrame:CGRectZero];
    _logView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_logView];

    [NSLayoutConstraint activateConstraints:@[
        [_bannerLabel.topAnchor      constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor constant:12],
        [_bannerLabel.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor constant:12],
        [_bannerLabel.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12],

        [separator.topAnchor      constraintEqualToAnchor:_bannerLabel.bottomAnchor constant:12],
        [separator.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [separator.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [separator.heightAnchor   constraintEqualToConstant:0.5],

        [_logView.topAnchor      constraintEqualToAnchor:separator.bottomAnchor],
        [_logView.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],
        [_logView.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [_logView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
    ]];
}

- (void)copyFullLog:(id)sender {
    (void)sender;

    NSString *snapshot = log_inapp_buffer_snapshot() ?: @"";
    NSString *title = snapshot.length ? @"Log Copied" : @"Log Empty";
    NSString *message = nil;
    if (snapshot.length) {
        UIPasteboard.generalPasteboard.string = snapshot;
        message = [NSString stringWithFormat:@"Copied %lu characters.", (unsigned long)snapshot.length];
    } else {
        message = @"There is no log text to copy yet.";
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)copyRelevantLog:(id)sender {
    (void)sender;

    NSString *snapshot = log_inapp_buffer_snapshot() ?: @"";
    NSString *filtered = [self relevantLogExcerptFromSnapshot:snapshot];
    NSString *title = filtered.length ? @"Relevant Log Copied" : @"No Relevant Lines";
    NSString *message = nil;
    if (filtered.length) {
        UIPasteboard.generalPasteboard.string = filtered;
        message = [NSString stringWithFormat:@"Copied %lu of %lu characters.",
                   (unsigned long)filtered.length,
                   (unsigned long)snapshot.length];
    } else {
        message = @"No Spotlight diagnostic lines were found.";
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (NSString *)relevantLogExcerptFromSnapshot:(NSString *)snapshot {
    if (![snapshot isKindOfClass:NSString.class] || snapshot.length == 0) return @"";

    NSMutableArray<NSString *> *snapshotLines = [NSMutableArray array];
    [snapshot enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
        (void)stop;
        if (line.length > 0) [snapshotLines addObject:line];
    }];
    if (snapshotLines.count == 0) return @"";

    // SnowBoard Remix has its own compact relevant-log view. Select the most
    // recent apply/restore run and retain its progress, failure summary, and
    // staged-versus-IconServices alpha measurements.
    NSInteger remixBeginIndex = NSNotFound;
    for (NSInteger i = (NSInteger)snapshotLines.count - 1; i >= 0; i--) {
        NSString *line = snapshotLines[(NSUInteger)i];
        if ([line containsString:@"[SBR] cataloging"] ||
            [line containsString:@"[SBR] restoring 1/"] ||
            [line containsString:@"[SBR] Authenticated vPhone installd backend"] ||
            [line containsString:@"[SBR] Establishing and validating kernel read/write"]) {
            remixBeginIndex = i;
            break;
        }
    }
    if (remixBeginIndex != NSNotFound) {
        NSUInteger remixLastIndex = snapshotLines.count - 1;
        for (NSUInteger i = (NSUInteger)remixBeginIndex;
             i < snapshotLines.count; i++) {
            NSString *line = snapshotLines[i];
            if (([line containsString:@"[OK] Apply Theme:"] ||
                 [line containsString:@"[WARN] Apply Theme:"] ||
                 [line containsString:@"[OK] Restore All Icons:"] ||
                 [line containsString:@"[WARN] Restore All Icons:"])) {
                remixLastIndex = i;
                break;
            }
        }
        NSMutableArray<NSString *> *remixLines = [NSMutableArray array];
        for (NSUInteger i = (NSUInteger)remixBeginIndex;
             i <= remixLastIndex; i++) {
            NSString *line = snapshotLines[i];
            if ([line containsString:@"[SBR]"] ||
                [line containsString:@"[SBR_ALPHA]"] ||
                [line containsString:@"[OK] Apply Theme:"] ||
                [line containsString:@"[WARN] Apply Theme:"] ||
                [line containsString:@"[OK] Restore All Icons:"] ||
                [line containsString:@"[WARN] Restore All Icons:"]) {
                [remixLines addObject:line];
            }
        }
        if (remixLines.count > 0) {
            [remixLines insertObject:[NSString stringWithFormat:
                @"[KSLOP] Latest SBR apply / restore run (%lu lines from %lu chars)",
                (unsigned long)remixLines.count,
                (unsigned long)snapshot.length] atIndex:0];
            return [remixLines componentsJoinedByString:@"\n"];
        }
    }

    // Explicit action markers are emitted before log_session_begin, so they
    // remain useful in the in-app ring buffer even when a session file was
    // truncated or a phase failed before its summary. Older runs have no
    // action marker; the fallback anchors below retain compatibility with
    // their preflight/selection traces.
    NSArray<NSString *> *actionMarkers = @[
        @"[ICONSERVICES_LAB] action-begin action=",
        @"[ICONSERVICES_MATERIALIZE] selection",
        @"[ICONSERVICES_LAB] local-sandbox-preflight",
        @"[ICONSERVICES_LAB] begin ",
    ];
    NSInteger beginIndex = NSNotFound;
    for (NSInteger i = (NSInteger)snapshotLines.count - 1; i >= 0; i--) {
        NSString *line = snapshotLines[(NSUInteger)i];
        if ([line containsString:actionMarkers[0]]) {
            beginIndex = i;
            break;
        }
    }
    if (beginIndex == NSNotFound) {
        // Search the fallback anchors independently, choosing the newest
        // anchor among them. This handles a fresh verify after an earlier
        // materializer summary and partial prearm failures without allowing
        // the old summary to swallow later verification lines.
        for (NSInteger i = (NSInteger)snapshotLines.count - 1; i >= 0; i--) {
            NSString *line = snapshotLines[(NSUInteger)i];
            BOOL anchor = NO;
            for (NSString *marker in [actionMarkers subarrayWithRange:NSMakeRange(1, actionMarkers.count - 1)]) {
                if ([line containsString:marker]) {
                    anchor = YES;
                    break;
                }
            }
            if (anchor) {
                beginIndex = i;
                break;
            }
        }
    }

    // A completion marker bounds a finished run. If a transport timeout or
    // exception prevented it, retain through the current ring-buffer tail so
    // the partial failure and its diagnostics are visible.
    NSUInteger firstIndex = beginIndex == NSNotFound
        ? 0 : (NSUInteger)beginIndex;
    NSUInteger lastIndex = snapshotLines.count - 1;
    if (beginIndex != NSNotFound) {
        for (NSUInteger i = firstIndex; i < snapshotLines.count; i++) {
            if ([snapshotLines[i] containsString:
                    @"[ICONSERVICES_LAB] action-complete action="]) {
                lastIndex = i;
                break;
            }
        }
    }

    // A blocked retry or an emergency action needs the attempt that armed
    // recovery. Keep that attempt and the subsequent recovery chain when it
    // is still in the ring buffer; never cross a successful emergency restore.
    BOOL needsRecoveryContext = NO;
    for (NSUInteger i = firstIndex; i <= lastIndex; i++) {
        NSString *line = snapshotLines[i];
        if ([line containsString:@"blocked: recovery is pending"] ||
            [line containsString:@"Emergency begin"] ||
            [line containsString:@"action-begin action=Inspect Issued Generation Recovery"] ||
            [line containsString:@"action-begin action=Spotlight IconServices Emergency Restore"]) {
            needsRecoveryContext = YES;
        }
    }
    BOOL causalAttemptFound = NO;
    if (needsRecoveryContext && firstIndex > 0) {
        NSInteger causalLine = NSNotFound;
        for (NSInteger i = (NSInteger)firstIndex - 1; i >= 0; i--) {
            NSString *line = snapshotLines[(NSUInteger)i];
            if ([line containsString:@"action-complete action=Spotlight IconServices Emergency Restore"] &&
                [line containsString:@" ok=1"]) {
                break;
            }
            if ([line containsString:@"[ICONSERVICES_MATERIALIZE] selection"] ||
                [line containsString:@"[ICONSERVICES_MATERIALIZE] context "] ||
                [line containsString:@"[ICONSERVICES_MATERIALIZE] prearm before "] ||
                [line containsString:@"[ICONSERVICES_MATERIALIZE] summary "]) {
                causalLine = i;
                break;
            }
        }
        if (causalLine != NSNotFound) {
            firstIndex = (NSUInteger)causalLine;
            causalAttemptFound = YES;
            for (NSInteger i = causalLine; i >= 0; i--) {
                NSString *line = snapshotLines[(NSUInteger)i];
                if ([line containsString:actionMarkers[0]]) {
                    firstIndex = (NSUInteger)i;
                    break;
                }
                // Older builds lack action markers. Include their selection
                // boundary, but do not absorb the preceding completed run.
                if ([line containsString:@"[ICONSERVICES_MATERIALIZE] selection"]) {
                    firstIndex = (NSUInteger)i;
                }
                if (i < causalLine &&
                    ([line containsString:@"[ICONSERVICES_LAB] action-complete action="] ||
                     [line containsString:@"[ICONSERVICES_MATERIALIZE] Completed "])) {
                    break;
                }
            }
        }
    }

    // Keep the full materialize/lab families plus the RemoteCall and host
    // lifecycle diagnostics that explain channel closure or abandonment.
    // This intentionally excludes unrelated app logs while preserving all
    // generation/preflight/record/bag/RC/emergency lines in the selected run.
    NSArray<NSString *> *families = @[
        @"[ICONSERVICES_MATERIALIZE]",
        @"[ICONSERVICES_RECOVERY]",
        @"[ICONSERVICES_LAB]",
        @"[ICONSERVICES_STORE_SURFACE]",
        @"[ICONSERVICES_STORE_STATE]",
        @"[ICONSERVICES_WRITER_STATE]",
        @"[ICONSERVICES_AGENT_PREFLIGHT]",
        @"[ICONSERVICES_AGENT_RESPONSE]",
        @"[ICONSERVICES_AGENT_PUBLISH]",
        @"[ICONSERVICES_AGENT_RESTORE]",
        @"[RC]",
        @"[SPOTLIGHT] host-session",
        @"[SPOTLIGHT] host-open",
        @"Don't receive second exception on new thread",
    ];
    NSMutableArray<NSString *> *lines = [NSMutableArray array];
    for (NSUInteger i = firstIndex; i <= lastIndex; i++) {
        NSString *line = snapshotLines[i];
        for (NSString *family in families) {
            if ([line containsString:family]) {
                [lines addObject:line];
                break;
            }
        }
    }
    if (lines.count == 0) return @"";

    NSString *header = [NSString stringWithFormat:
        @"[KSLOP] Latest Spotlight stock68 materialization / recovery %@ (%lu lines from %lu chars)",
        causalAttemptFound ? @"chain" : @"run",
        (unsigned long)lines.count,
        (unsigned long)snapshot.length];
    [lines insertObject:header atIndex:0];
    if (needsRecoveryContext && !causalAttemptFound) {
        [lines insertObject:@"[KSLOP] The earlier materialization attempt is unavailable in this snapshot; this excerpt cannot establish whether generation was dispatched."
                    atIndex:1];
    }
    return [lines componentsJoinedByString:@"\n"];
}

- (NSAttributedString *)buildBannerText {
    NSBundle *b = [NSBundle mainBundle];
    NSDictionary *info = b.infoDictionary;
    NSString *shortVer = info[@"CFBundleShortVersionString"] ?: @"?";
    NSString *build = info[@"CFBundleVersion"] ?: @"?";

    struct utsname u = {0};
    const char *machine = "device";
    if (uname(&u) == 0 && u.machine[0])
        machine = u.machine;
    NSString *ios = UIDevice.currentDevice.systemVersion ?: @"?";

    NSString *banner = [NSString stringWithFormat:
        @"     ╭───────────╮\n"
        @"     │ ▄▄▄▄▄▄▄▄▄ │\n"
        @"     ├───────────┤\n"
        @"     │ ░░░░░░░░░ │   K S L O P\n"
        @"     │ ░░░ K ░░░ │   %@ (%@)\n"
        @"     │ ░░░░░░░░░ │   %s • iOS %@\n"
        @"     │ ░░░░░░░░░ │\n"
        @"     ╰───────────╯",
        shortVer, build, machine, ios];

    NSMutableParagraphStyle *para = [[NSMutableParagraphStyle alloc] init];
    para.lineSpacing = 2.0;

    return [[NSAttributedString alloc] initWithString:banner attributes:@{
        NSFontAttributeName: [UIFont monospacedSystemFontOfSize:11.5 weight:UIFontWeightRegular],
        NSForegroundColorAttributeName: [UIColor colorWithWhite:0.86 alpha:1.0],
        NSParagraphStyleAttributeName: para,
    }];
}

@end
