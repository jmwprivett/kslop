//
//  QueueReviewViewController.m
//  Cyanide
//

#import "QueueReviewViewController.h"
#import "PackageQueue.h"
#import "PackageCatalog.h"
#import "CNDQueuedActionCatalog.h"
#import "InstallProgressViewController.h"
#import "../LogTextView.h"

typedef NS_ENUM(NSInteger, QueueReviewSection) {
    QueueReviewSectionStandalone = 0,
    QueueReviewSectionInstall,
    QueueReviewSectionUninstall,
    QueueReviewSectionReApply,
    QueueReviewSectionCount,
};

@interface QueueReviewViewController () <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UIButton *confirmButton;
@property (nonatomic, strong) UIButton *clearButton;
@property (nonatomic, strong) UILabel *emptyLabel;
@end

@implementation QueueReviewViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Queue";
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.translatesAutoresizingMaskIntoConstraints = NO;
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    [self.view addSubview:self.tableView];

    UIView *footer = [self buildFooter];
    footer.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:footer];

    self.emptyLabel = [[UILabel alloc] init];
    self.emptyLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.emptyLabel.text = @"No pending changes\nQueue packages or system actions to begin";
    self.emptyLabel.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightMedium];
    self.emptyLabel.textColor = UIColor.tertiaryLabelColor;
    self.emptyLabel.textAlignment = NSTextAlignmentCenter;
    self.emptyLabel.numberOfLines = 0;
    [self.view addSubview:self.emptyLabel];

    [NSLayoutConstraint activateConstraints:@[
        [self.tableView.topAnchor      constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
        [self.tableView.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [self.tableView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [self.tableView.bottomAnchor   constraintEqualToAnchor:footer.topAnchor],

        [footer.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [footer.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [footer.bottomAnchor   constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],

        [self.emptyLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.emptyLabel.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [self.emptyLabel.leadingAnchor  constraintGreaterThanOrEqualToAnchor:self.view.leadingAnchor constant:24.0],
        [self.emptyLabel.trailingAnchor constraintLessThanOrEqualToAnchor:self.view.trailingAnchor constant:-24.0],
    ]];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(queueChanged:)
                                                 name:PackageQueueDidChangeNotification
                                               object:nil];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self refreshUI];
}

- (UIView *)buildFooter
{
    UIView *container = [[UIView alloc] init];
    container.backgroundColor = UIColor.systemGroupedBackgroundColor;

    UIButtonConfiguration *confirmCfg = [UIButtonConfiguration filledButtonConfiguration];
    confirmCfg.title = @"Confirm";
    confirmCfg.cornerStyle = UIButtonConfigurationCornerStyleLarge;
    confirmCfg.titleTextAttributesTransformer = ^NSDictionary<NSAttributedStringKey,id> *(NSDictionary<NSAttributedStringKey,id> *incoming) {
        NSMutableDictionary *attrs = [incoming mutableCopy];
        attrs[NSFontAttributeName] = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];
        return attrs;
    };
    self.confirmButton = [UIButton buttonWithConfiguration:confirmCfg primaryAction:[UIAction actionWithHandler:^(UIAction *_) {
        [self didTapConfirm];
    }]];
    self.confirmButton.translatesAutoresizingMaskIntoConstraints = NO;
    [container addSubview:self.confirmButton];

    UIButtonConfiguration *clearCfg = [UIButtonConfiguration plainButtonConfiguration];
    clearCfg.title = @"Clear Queue";
    clearCfg.baseForegroundColor = UIColor.systemRedColor;
    clearCfg.titleTextAttributesTransformer = ^NSDictionary<NSAttributedStringKey,id> *(NSDictionary<NSAttributedStringKey,id> *incoming) {
        NSMutableDictionary *attrs = [incoming mutableCopy];
        attrs[NSFontAttributeName] = [UIFont systemFontOfSize:14.0 weight:UIFontWeightMedium];
        return attrs;
    };
    self.clearButton = [UIButton buttonWithConfiguration:clearCfg primaryAction:[UIAction actionWithHandler:^(UIAction *_) {
        [self didTapClear];
    }]];
    self.clearButton.translatesAutoresizingMaskIntoConstraints = NO;
    [container addSubview:self.clearButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.confirmButton.topAnchor      constraintEqualToAnchor:container.topAnchor constant:8.0],
        [self.confirmButton.leadingAnchor  constraintEqualToAnchor:container.leadingAnchor constant:16.0],
        [self.confirmButton.trailingAnchor constraintEqualToAnchor:container.trailingAnchor constant:-16.0],
        [self.confirmButton.heightAnchor   constraintEqualToConstant:50.0],

        [self.clearButton.topAnchor        constraintEqualToAnchor:self.confirmButton.bottomAnchor constant:2.0],
        [self.clearButton.centerXAnchor    constraintEqualToAnchor:container.centerXAnchor],
        [self.clearButton.bottomAnchor     constraintEqualToAnchor:container.bottomAnchor constant:-8.0],
    ]];
    return container;
}

- (void)refreshUI
{
    [self.tableView reloadData];
    [self updateSharedRespringHeader];
    NSInteger count = [PackageQueue sharedQueue].pendingCount;
    self.emptyLabel.hidden = (count > 0);
    self.tableView.hidden = (count == 0);
    self.confirmButton.enabled = (count > 0);
    CNDQueuedTransaction *transaction =
        [PackageQueue sharedQueue].durableTransaction;
    self.clearButton.enabled = [PackageQueue sharedQueue].canClear;

    NSString *confirmTitle;
    if (transaction.preRespringSpringBoardPID > 1) {
        confirmTitle = @"Continue After Respring";
    } else if (count == 1) {
        confirmTitle = @"Confirm 1 Change";
    } else if (count > 1) {
        confirmTitle = [NSString stringWithFormat:@"Confirm %ld Changes", (long)count];
    } else {
        confirmTitle = @"Confirm";
    }
    UIButtonConfiguration *cfg = self.confirmButton.configuration;
    cfg.title = confirmTitle;
    self.confirmButton.configuration = cfg;
}

- (BOOL)queueRequiresSharedRespring
{
    CNDQueuedTransaction *transaction =
        [PackageQueue sharedQueue].durableTransaction;
    if (!transaction) return NO;
    if (transaction.preRespringSpringBoardPID > 1 ||
        transaction.state == CNDQueuedTransactionStateAwaitingRespring ||
        CNDQueuedActionsRequireRespring(transaction.actions)) return YES;
    for (CNDQueuedAction *action in transaction.actions) {
        if (action.phase != CNDQueuedActionPhaseAutomatic) return YES;
    }
    return NO;
}

- (UIView *)sharedRespringHeaderView
{
    CGFloat width = self.tableView.bounds.size.width;
    if (width <= 0.0) width = self.view.bounds.size.width;
    if (width <= 0.0) width = UIScreen.mainScreen.bounds.size.width;

    UIView *container = [[UIView alloc] initWithFrame:CGRectMake(0.0, 0.0, width, 1.0)];
    container.backgroundColor = UIColor.systemGroupedBackgroundColor;

    UIView *card = [[UIView alloc] init];
    card.translatesAutoresizingMaskIntoConstraints = NO;
    card.backgroundColor = [UIColor.systemIndigoColor colorWithAlphaComponent:0.12];
    card.layer.cornerRadius = 16.0;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor = [UIColor.systemIndigoColor colorWithAlphaComponent:0.25].CGColor;
    [container addSubview:card];

    UIImageView *icon = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"arrow.triangle.2.circlepath.circle.fill"]];
    icon.translatesAutoresizingMaskIntoConstraints = NO;
    icon.tintColor = UIColor.systemIndigoColor;
    icon.contentMode = UIViewContentModeScaleAspectFit;
    [card addSubview:icon];

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"One shared respring";
    title.font = [UIFont systemFontOfSize:16.0 weight:UIFontWeightBold];
    title.textColor = UIColor.labelColor;
    [card addSubview:title];

    UILabel *body = [[UILabel alloc] init];
    body.translatesAutoresizingMaskIntoConstraints = NO;
    body.text = @"Persistent icon and system-file changes run first. Cyanide then resprings once and resumes the remaining presentation actions from the saved queue.";
    body.font = [UIFont systemFontOfSize:13.0 weight:UIFontWeightRegular];
    body.textColor = UIColor.secondaryLabelColor;
    body.numberOfLines = 0;
    [card addSubview:body];

    [NSLayoutConstraint activateConstraints:@[
        [card.topAnchor constraintEqualToAnchor:container.topAnchor constant:12.0],
        [card.leadingAnchor constraintEqualToAnchor:container.leadingAnchor constant:16.0],
        [card.trailingAnchor constraintEqualToAnchor:container.trailingAnchor constant:-16.0],
        [card.bottomAnchor constraintEqualToAnchor:container.bottomAnchor constant:-8.0],

        [icon.topAnchor constraintEqualToAnchor:card.topAnchor constant:14.0],
        [icon.leadingAnchor constraintEqualToAnchor:card.leadingAnchor constant:14.0],
        [icon.widthAnchor constraintEqualToConstant:24.0],
        [icon.heightAnchor constraintEqualToConstant:24.0],

        [title.topAnchor constraintEqualToAnchor:card.topAnchor constant:12.0],
        [title.leadingAnchor constraintEqualToAnchor:icon.trailingAnchor constant:10.0],
        [title.trailingAnchor constraintEqualToAnchor:card.trailingAnchor constant:-14.0],

        [body.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:4.0],
        [body.leadingAnchor constraintEqualToAnchor:title.leadingAnchor],
        [body.trailingAnchor constraintEqualToAnchor:title.trailingAnchor],
        [body.bottomAnchor constraintEqualToAnchor:card.bottomAnchor constant:-12.0],
    ]];

    CGSize size = [container systemLayoutSizeFittingSize:CGSizeMake(width, 0.0)
                           withHorizontalFittingPriority:UILayoutPriorityRequired
                                 verticalFittingPriority:UILayoutPriorityFittingSizeLevel];
    container.frame = CGRectMake(0.0, 0.0, width, ceil(size.height));
    return container;
}

- (void)updateSharedRespringHeader
{
    if (![self queueRequiresSharedRespring]) {
        self.tableView.tableHeaderView = nil;
        return;
    }
    self.tableView.tableHeaderView = [self sharedRespringHeaderView];
}

- (void)queueChanged:(NSNotification *)note
{
    [self refreshUI];
}

#pragma mark - Table

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    return QueueReviewSectionCount;
}

- (NSArray<Package *> *)reApplyPackages
{
    if ([self queueRequiresSharedRespring]) return @[];

    PackageQueue *q = [PackageQueue sharedQueue];
    NSMutableArray<Package *> *out = [NSMutableArray array];
    for (Package *p in [PackageCatalog allPackages]) {
        if (!p.isInstalled) continue;
        if ([q intentForPackage:p] == PackageQueueIntentUninstall) continue;
        [out addObject:p];
    }
    return out;
}

- (NSArray<Package *> *)packagesForSection:(NSInteger)section
{
    PackageQueue *q = [PackageQueue sharedQueue];
    switch ((QueueReviewSection)section) {
        case QueueReviewSectionStandalone: return @[];
        case QueueReviewSectionInstall:   return q.queuedInstalls;
        case QueueReviewSectionUninstall: return q.queuedUninstalls;
        case QueueReviewSectionReApply:   return [self reApplyPackages];
        case QueueReviewSectionCount:     return @[];
    }
    return @[];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    if ((QueueReviewSection)section == QueueReviewSectionStandalone) {
        return (NSInteger)[PackageQueue sharedQueue].queuedStandaloneActions.count;
    }
    return (NSInteger)[self packagesForSection:section].count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if ((QueueReviewSection)section == QueueReviewSectionStandalone) {
        NSInteger count = (NSInteger)[PackageQueue sharedQueue].queuedStandaloneActions.count;
        return count > 0
            ? [NSString stringWithFormat:@"System Actions  ·  %ld", (long)count]
            : nil;
    }
    NSArray<Package *> *list = [self packagesForSection:section];
    if (list.count == 0) return nil;
    PackageInstallKind commonKind = list.firstObject.kind;
    BOOL allSameKind = YES;
    for (Package *pkg in list) {
        if (pkg.kind != commonKind) {
            allSameKind = NO;
            break;
        }
    }
    NSString *label;
    switch ((QueueReviewSection)section) {
        case QueueReviewSectionStandalone: return nil;
        case QueueReviewSectionInstall:
            if (allSameKind && commonKind == PackageInstallKindOTA) {
                label = @"Disable";
            } else if (allSameKind && commonKind == PackageInstallKindNanoRegistry) {
                label = @"Apply";
            } else if (allSameKind && commonKind == PackageInstallKindCallRecordingSound) {
                label = @"Silence";
            } else if (allSameKind && commonKind == PackageInstallKindHideHomeBar) {
                label = @"Hide";
            } else if (allSameKind && (commonKind == PackageInstallKindFontChanger ||
                                       commonKind == PackageInstallKindControlCenterTheming ||
                                       commonKind == PackageInstallKindLockscreenGlyphs)) {
                label = @"Apply";
            } else {
                label = @"Activate";
            }
            break;
        case QueueReviewSectionUninstall:
            if (allSameKind && commonKind == PackageInstallKindOTA) {
                label = @"Enable";
            } else if (allSameKind && commonKind == PackageInstallKindNanoRegistry) {
                label = @"Remove";
            } else if (allSameKind && commonKind == PackageInstallKindCallRecordingSound) {
                label = @"Restore";
            } else if (allSameKind && commonKind == PackageInstallKindHideHomeBar) {
                label = @"Restore";
            } else if (allSameKind && (commonKind == PackageInstallKindFontChanger ||
                                       commonKind == PackageInstallKindControlCenterTheming ||
                                       commonKind == PackageInstallKindLockscreenGlyphs)) {
                label = @"Restore";
            } else {
                label = @"Deactivate";
            }
            break;
        case QueueReviewSectionReApply:   label = @"Already Active";   break;
        default:                          return nil;
    }
    return [NSString stringWithFormat:@"%@  ·  %ld", label, (long)list.count];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    switch ((QueueReviewSection)section) {
        case QueueReviewSectionStandalone:
            return [PackageQueue sharedQueue].queuedStandaloneActions.count > 0
                ? @"SnowBoard Apply/Restore, Transparency Fix, SpringBoard Fixes, and Spotlight Fixes are independent durable queue actions. Conflicting desired states replace one another."
                : nil;
        case QueueReviewSectionInstall:
            if (![self queueRequiresSharedRespring]) return nil;
            return @"System-file changes run before the queue's single shared respring.";
        case QueueReviewSectionReApply:
            if ([self reApplyPackages].count == 0) return nil;
            return @"These are already installed, not new pending changes. Confirming re-runs the chain so RemoteCall-backed tweaks come back after a force-quit. To stop one from running, deactivate it from the Installer tab, or use Reset All Packages in Settings → Quick Actions.";
        default:
            return nil;
    }
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"QueueRow"];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"QueueRow"];
    }
    if ((QueueReviewSection)indexPath.section == QueueReviewSectionStandalone) {
        NSArray<CNDQueuedAction *> *actions =
            [PackageQueue sharedQueue].queuedStandaloneActions;
        if (indexPath.row >= (NSInteger)actions.count) return cell;
        CNDQueuedAction *action = actions[indexPath.row];
        if ([action.kind isEqualToString:CNDQueuedActionKindSnowBoardRemix]) {
            BOOL apply = [action.operation isEqualToString:
                CNDQueuedActionOperationApplyTheme];
            cell.textLabel.text = apply
                ? @"Apply SnowBoard Theme" : @"Restore All Icons";
            cell.detailTextLabel.text = apply
                ? @"Persistent icon publication before respring"
                : @"Persistent stock restoration before respring";
            cell.imageView.image = [UIImage systemImageNamed:
                apply ? @"square.stack.3d.up.fill" : @"arrow.uturn.backward.circle.fill"];
            cell.detailTextLabel.textColor = apply
                ? UIColor.systemGreenColor : UIColor.systemRedColor;
        } else if ([action.kind isEqualToString:
                       CNDQueuedActionKindTransparencyFix]) {
            BOOL apply = [action.operation isEqualToString:
                CNDQueuedActionOperationApplyTransparencyFix];
            cell.textLabel.text = apply
                ? @"Apply Transparency Fix"
                : @"Restore Transparency Fix";
            cell.detailTextLabel.text = apply
                ? @"Adaptive · guarded per-boot shared-cache redirect"
                : @"Adaptive · restore original shared-cache entry";
            cell.imageView.image = [UIImage systemImageNamed:
                apply ? @"circle.lefthalf.filled" : @"arrow.uturn.backward.circle.fill"];
            cell.detailTextLabel.textColor = apply
                ? UIColor.systemGreenColor : UIColor.systemRedColor;
        } else if ([action.kind isEqualToString:
                       CNDQueuedActionKindSpringBoardFixes]) {
            BOOL transparency = [action.parameters[
                CNDQueuedActionParameterTransparencyEnabled] boolValue];
            cell.textLabel.text = @"SpringBoard Fixes";
            cell.detailTextLabel.text = transparency
                ? @"Adaptive · transparency + Clock/Calendar repair"
                : @"Invalid snapshot · transparency disabled";
            cell.imageView.image = [UIImage systemImageNamed:@"iphone"];
            cell.detailTextLabel.textColor = UIColor.systemIndigoColor;
        } else {
            BOOL transparency = [action.parameters[
                CNDQueuedActionParameterTransparencyEnabled] boolValue];
            cell.textLabel.text = @"Spotlight Fixes";
            cell.detailTextLabel.text = transparency
                ? @"Adaptive · assertion + presentation repair"
                : @"Adaptive · Spotlight lifetime assertion";
            cell.imageView.image = [UIImage systemImageNamed:@"magnifyingglass"];
            cell.detailTextLabel.textColor = UIColor.systemIndigoColor;
        }
        cell.textLabel.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];
        cell.detailTextLabel.font = [UIFont systemFontOfSize:12.0];
        cell.imageView.tintColor = self.view.tintColor;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.accessoryView = nil;
        cell.accessoryType = UITableViewCellAccessoryNone;
        return cell;
    }
    NSArray<Package *> *packages = [self packagesForSection:indexPath.section];
    if (indexPath.row >= (NSInteger)packages.count) {
        cell.textLabel.text = @"No longer pending";
        cell.textLabel.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightRegular];
        cell.detailTextLabel.text = @"This queue row was already applied or cleared.";
        cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
        cell.detailTextLabel.font = [UIFont systemFontOfSize:12.0];
        cell.imageView.image = [UIImage systemImageNamed:@"checkmark.circle"];
        cell.imageView.tintColor = UIColor.tertiaryLabelColor;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        cell.accessoryView = nil;
        cell.accessoryType = UITableViewCellAccessoryNone;
        return cell;
    }

    Package *pkg = packages[indexPath.row];
    cell.textLabel.text = pkg.name;
    cell.textLabel.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];

    QueueReviewSection s = (QueueReviewSection)indexPath.section;
    switch (s) {
        case QueueReviewSectionStandalone:
            break;
        case QueueReviewSectionInstall:
            switch (pkg.kind) {
                case PackageInstallKindOTA:
                    cell.detailTextLabel.text = @"Pending OTA disable";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                case PackageInstallKindNanoRegistry:
                    cell.detailTextLabel.text = @"Pending override apply";
                    cell.detailTextLabel.textColor = self.view.tintColor;
                    break;
                case PackageInstallKindCallRecordingSound:
                    cell.detailTextLabel.text = @"Pending sound silence";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                case PackageInstallKindHideHomeBar:
                    cell.detailTextLabel.text = @"Before shared respring";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                case PackageInstallKindFontChanger:
                    cell.detailTextLabel.text = @"Pending font apply before respring";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                case PackageInstallKindControlCenterTheming:
                    cell.detailTextLabel.text = @"Pending CC apply before respring";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                case PackageInstallKindLockscreenGlyphs:
                    cell.detailTextLabel.text = @"Pending glyph apply before respring";
                    cell.detailTextLabel.textColor = UIColor.systemOrangeColor;
                    break;
                default:
                    cell.detailTextLabel.text = @"Activation pending";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
            }
            break;
        case QueueReviewSectionUninstall:
            switch (pkg.kind) {
                case PackageInstallKindOTA:
                    cell.detailTextLabel.text = @"Pending OTA enable";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                case PackageInstallKindNanoRegistry:
                    cell.detailTextLabel.text = @"Pending override remove";
                    cell.detailTextLabel.textColor = UIColor.systemRedColor;
                    break;
                case PackageInstallKindCallRecordingSound:
                    cell.detailTextLabel.text = @"Pending sound restore";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                case PackageInstallKindHideHomeBar:
                    cell.detailTextLabel.text = @"Pending restore before respring";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                case PackageInstallKindFontChanger:
                    cell.detailTextLabel.text = @"Pending font restore before respring";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                case PackageInstallKindControlCenterTheming:
                    cell.detailTextLabel.text = @"Pending CC restore before respring";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                case PackageInstallKindLockscreenGlyphs:
                    cell.detailTextLabel.text = @"Pending glyph restore before respring";
                    cell.detailTextLabel.textColor = UIColor.systemGreenColor;
                    break;
                default:
                    cell.detailTextLabel.text = @"Deactivation pending";
                    cell.detailTextLabel.textColor = UIColor.systemRedColor;
                    break;
            }
            break;
        case QueueReviewSectionReApply:
            cell.detailTextLabel.text = @"Active; will refresh";
            cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
            break;
        default:
            cell.detailTextLabel.text = nil;
            break;
    }
    cell.detailTextLabel.font = [UIFont systemFontOfSize:12.0];
    cell.imageView.image = [UIImage systemImageNamed:pkg.symbolName];
    cell.imageView.tintColor = (s == QueueReviewSectionReApply)
        ? UIColor.tertiaryLabelColor
        : self.view.tintColor;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    cell.accessoryView = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    return cell;
}

- (UISwipeActionsConfiguration *)tableView:(UITableView *)tableView
    trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
{
    CNDQueuedTransaction *transaction =
        [PackageQueue sharedQueue].durableTransaction;
    if (transaction &&
        transaction.state != CNDQueuedTransactionStateCollecting) return nil;
    // Swipe-to-remove only applies to the pending queue rows. "Will Re-Apply"
    // is informational — to drop one, the user uninstalls it from the
    // Installer tab or runs Reset All Packages.
    QueueReviewSection s = (QueueReviewSection)indexPath.section;
    if (s == QueueReviewSectionStandalone) {
        NSArray<CNDQueuedAction *> *actions =
            [PackageQueue sharedQueue].queuedStandaloneActions;
        if (indexPath.row >= (NSInteger)actions.count) return nil;
        CNDQueuedAction *queuedAction = actions[indexPath.row];
        NSString *conflictKey = CNDQueuedActionConflictKey(queuedAction);
        UIContextualAction *remove = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Remove"
                              handler:^(UIContextualAction *action,
                                        __kindof UIView *sourceView,
                                        void (^completionHandler)(BOOL)) {
            (void)action; (void)sourceView;
            BOOL removed = [[PackageQueue sharedQueue]
                removeStandaloneActionForConflictKey:conflictKey];
            completionHandler(removed);
        }];
        return [UISwipeActionsConfiguration configurationWithActions:@[remove]];
    }
    if (s != QueueReviewSectionInstall && s != QueueReviewSectionUninstall) return nil;

    NSArray<Package *> *packages = [self packagesForSection:indexPath.section];
    if (indexPath.row >= (NSInteger)packages.count) return nil;

    Package *pkg = packages[indexPath.row];
    UIContextualAction *remove = [UIContextualAction contextualActionWithStyle:UIContextualActionStyleDestructive
                                                                         title:@"Remove"
                                                                       handler:^(UIContextualAction * _Nonnull action, __kindof UIView * _Nonnull sourceView, void (^ _Nonnull completionHandler)(BOOL)) {
        [[PackageQueue sharedQueue] removePackage:pkg];
        completionHandler(YES);
    }];
    return [UISwipeActionsConfiguration configurationWithActions:@[remove]];
}

#pragma mark - Actions

- (void)didTapConfirm
{
    if ([PackageQueue sharedQueue].pendingCount == 0) return;
    NSInteger count = [PackageQueue sharedQueue].pendingCount;

    InstallProgressViewController *vc = [[InstallProgressViewController alloc] init];
    vc.expectsPackageQueueCompletion = YES;
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:vc];
    nav.modalPresentationStyle = UIModalPresentationAutomatic;
    [self presentViewController:nav animated:YES completion:^{
        log_user("[INSTALLER] ── Applying %ld pending change(s) ──\n", (long)count);
        [[PackageQueue sharedQueue] commit];
    }];
}

- (void)didTapClear
{
    if ([PackageQueue sharedQueue].pendingCount == 0) return;
    CNDQueuedTransaction *transaction =
        [PackageQueue sharedQueue].durableTransaction;
    BOOL executionStarted = transaction &&
        transaction.state != CNDQueuedTransactionStateCollecting;
    NSString *message = executionStarted
        ? @"Discard the remaining saved plan? Changes that already completed will not be undone."
        : @"Discard all pending package and system changes.";
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Clear Queue?"
                                                                message:message
                                                         preferredStyle:UIAlertControllerStyleAlert];
    [ac addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"Clear" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *_) {
        [[PackageQueue sharedQueue] clear];
    }]];
    [self presentViewController:ac animated:YES completion:nil];
}

@end
