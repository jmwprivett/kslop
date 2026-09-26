//
//  PackagesViewController.m
//  Cyanide
//

#import "PackagesViewController.h"
#import "PackageCatalog.h"
#import "PackageDetailViewController.h"
#import "PackageQueue.h"
#import "../SettingsViewController.h"

static NSString * const kPackageCellID         = @"PackageCell";
static NSString * const kGroupByCategoryDefault = @"installer.groupByCategory";
static NSString * const kReworkedSnowBoardIdentifier = @"com.darksword.snowboardlite";
static NSString * const kReworkedFontIdentifier     = @"com.darksword.font-changer";

@interface PackagesViewController () <UISearchResultsUpdating>
@property (nonatomic, copy)   NSArray<Package *> *allPackagesSorted;
@property (nonatomic, copy)   NSArray<Package *> *favoritePackages;
@property (nonatomic, copy)   NSArray<Package *> *reworkedPackages;
@property (nonatomic, copy)   NSArray<Package *> *flatPackages;        // shown when !groupByCategory
@property (nonatomic, copy)   NSArray<NSString *> *visibleCategories;  // shown when groupByCategory
@property (nonatomic, copy)   NSDictionary<NSString *, NSArray<Package *> *> *packagesByCategory;
@property (nonatomic, copy)   NSString *searchText;
@property (nonatomic, assign) BOOL groupByCategory;
@property (nonatomic, strong) UISearchController *searchCtl;
@end

@implementation PackagesViewController

- (BOOL)packageNeedsThemeBeforeInstall:(Package *)pkg
{
    return [pkg.identifier isEqualToString:@"com.darksword.themer"] &&
           !pkg.isInstalled &&
           !settings_themer_has_selected_theme();
}

- (BOOL)packageNeedsLiveWPVideoBeforeInstall:(Package *)pkg
{
    return [pkg.identifier isEqualToString:@"com.darksword.livewp"] &&
           !pkg.isInstalled &&
           ![SettingsViewController liveWPHasSelectedVideo];
}

- (BOOL)packageNeedsFontBeforeInstall:(Package *)pkg
{
    return pkg.kind == PackageInstallKindFontChanger &&
           !pkg.isInstalled &&
           !settings_font_changer_has_regular_font();
}

- (BOOL)presentQueueConflictIfNeededForPackage:(Package *)pkg intent:(PackageQueueIntent)intent
{
    NSString *reason = nil;
    if ([[PackageQueue sharedQueue] canQueueIntent:intent
                                       forPackage:pkg
                                           reason:&reason]) {
        return NO;
    }

    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"Run System Edit Alone"
                                            message:reason ?: @"This system edit must be the only pending queue item."
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
    return YES;
}

- (void)viewDidLoad
{
    [super viewDidLoad];
    self.title = @"Installer";
    self.navigationItem.title = @"Installer";

    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    if (![ud objectForKey:kGroupByCategoryDefault]) {
        [ud setBool:YES forKey:kGroupByCategoryDefault];
    }
    self.groupByCategory = [ud boolForKey:kGroupByCategoryDefault];
    self.searchText = @"";

    self.allPackagesSorted = [[PackageCatalog allPackages]
        sortedArrayUsingComparator:^NSComparisonResult(Package *a, Package *b) {
            return [a.name caseInsensitiveCompare:b.name];
        }];

    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 68.0;
    self.tableView.sectionFooterHeight = 4.0;
    if (@available(iOS 15.0, *)) {
        self.tableView.sectionHeaderTopPadding = 0.0;
    }

    // Search controller pinned in the nav bar so it shows above the table.
    self.searchCtl = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchCtl.searchResultsUpdater = self;
    self.searchCtl.obscuresBackgroundDuringPresentation = NO;
    self.searchCtl.searchBar.placeholder = @"Search tweaks";
    self.navigationItem.searchController = self.searchCtl;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;

    [self installSortBarButton];
    [self rebuildFilteredData];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(queueDidChange:)
                                                 name:PackageQueueDidChangeNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(queueDidChange:)
                                                 name:kSettingsActionsDidCompleteNotification
                                               object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(favoritesDidChange:)
                                                 name:PackageFavoritesDidChangeNotification
                                               object:nil];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    [self refreshCatalog];
    [self.tableView reloadData];
}

- (void)refreshCatalog
{
    // Re-fetch the catalog so toggles to the master experimental switch (which
    // changes which packages PackageCatalog returns) show up the next time
    // this view appears or the queue fires its change notification.
    self.allPackagesSorted = [[PackageCatalog allPackages]
        sortedArrayUsingComparator:^NSComparisonResult(Package *a, Package *b) {
            return [a.name caseInsensitiveCompare:b.name];
        }];
    [self rebuildFilteredData];
}

- (void)queueDidChange:(NSNotification *)note
{
    if (!self.isViewLoaded) return;
    [self refreshCatalog];
    [self.tableView reloadData];
}

- (void)favoritesDidChange:(NSNotification *)note
{
    (void)note;
    if (!self.isViewLoaded) return;
    [self rebuildFilteredData];
    [self.tableView reloadData];
}

#pragma mark - Sort menu

- (void)installSortBarButton
{
    UIAction *flat = [UIAction actionWithTitle:@"Alphabetical"
                                         image:[UIImage systemImageNamed:@"list.bullet"]
                                    identifier:nil
                                       handler:^(UIAction *_) {
        [self applyGroupByCategory:NO];
    }];
    flat.state = self.groupByCategory ? UIMenuElementStateOff : UIMenuElementStateOn;

    UIAction *byCat = [UIAction actionWithTitle:@"By Category"
                                          image:[UIImage systemImageNamed:@"folder"]
                                     identifier:nil
                                        handler:^(UIAction *_) {
        [self applyGroupByCategory:YES];
    }];
    byCat.state = self.groupByCategory ? UIMenuElementStateOn : UIMenuElementStateOff;

    UIMenu *menu = [UIMenu menuWithTitle:@"Sort" children:@[flat, byCat]];
    UIBarButtonItem *btn = [[UIBarButtonItem alloc]
        initWithImage:[UIImage systemImageNamed:@"line.3.horizontal.decrease.circle"]
                 menu:menu];
    self.navigationItem.rightBarButtonItem = btn;
}

- (void)applyGroupByCategory:(BOOL)group
{
    if (_groupByCategory == group) return;
    _groupByCategory = group;
    [[NSUserDefaults standardUserDefaults] setBool:group forKey:kGroupByCategoryDefault];
    [self installSortBarButton];
    [self rebuildFilteredData];
    [self.tableView reloadData];
}

#pragma mark - Search

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    NSString *q = searchController.searchBar.text ?: @"";
    if ([q isEqualToString:self.searchText]) return;
    self.searchText = q;
    [self rebuildFilteredData];
    [self.tableView reloadData];
}

#pragma mark - Filtering / bucketing

- (BOOL)package:(Package *)pkg matchesQuery:(NSString *)q
{
    if (q.length == 0) return YES;
    NSStringCompareOptions opt = NSCaseInsensitiveSearch | NSDiacriticInsensitiveSearch;
    if ([pkg.name             rangeOfString:q options:opt].location != NSNotFound) return YES;
    if ([pkg.shortDescription rangeOfString:q options:opt].location != NSNotFound) return YES;
    if ([pkg.category         rangeOfString:q options:opt].location != NSNotFound) return YES;
    return NO;
}

- (void)rebuildFilteredData
{
    NSMutableArray<Package *> *filtered = [NSMutableArray array];
    for (Package *p in self.allPackagesSorted) {
        if ([self package:p matchesQuery:self.searchText]) [filtered addObject:p];
    }
    NSMutableArray<Package *> *reworked = [NSMutableArray array];
    NSMutableArray<Package *> *remaining = [NSMutableArray array];
    NSSet<NSString *> *reworkedIdentifiers = [NSSet setWithObjects:
        kReworkedSnowBoardIdentifier, kReworkedFontIdentifier, nil];
    for (Package *package in filtered) {
        if ([reworkedIdentifiers containsObject:package.identifier]) {
            [reworked addObject:package];
        } else {
            [remaining addObject:package];
        }
    }
    [reworked sortUsingComparator:^NSComparisonResult(Package *a, Package *b) {
        BOOL aSnowBoard = [a.identifier isEqualToString:kReworkedSnowBoardIdentifier];
        BOOL bSnowBoard = [b.identifier isEqualToString:kReworkedSnowBoardIdentifier];
        if (aSnowBoard != bSnowBoard) return aSnowBoard ? NSOrderedAscending : NSOrderedDescending;
        return [a.name caseInsensitiveCompare:b.name];
    }];
    self.reworkedPackages = reworked;
    self.flatPackages = remaining;

    NSSet<NSString *> *favoriteIdentifiers = PackageFavoriteIdentifiers();
    NSMutableArray<Package *> *favorites = [NSMutableArray array];
    for (Package *package in filtered) {
        if ([favoriteIdentifiers containsObject:package.identifier]) {
            [favorites addObject:package];
        }
    }
    self.favoritePackages = favorites;

    if (!self.groupByCategory) {
        self.visibleCategories = nil;
        self.packagesByCategory = nil;
        return;
    }

    NSMutableArray<NSString *> *cats = [NSMutableArray array];
    NSMutableDictionary<NSString *, NSArray<Package *> *> *bucket = [NSMutableDictionary dictionary];
    for (NSString *cat in [PackageCatalog categoriesInOrder]) {
        NSMutableArray<Package *> *inCat = [NSMutableArray array];
        for (Package *p in remaining) {
            if ([p.category isEqualToString:cat]) [inCat addObject:p];
        }
        if (inCat.count > 0) {
            [cats addObject:cat];
            bucket[cat] = inCat;
        }
    }
    self.visibleCategories = cats;
    self.packagesByCategory = bucket;
}

#pragma mark - Data source

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    // Favorites is always section zero; Reworked is the curated section
    // immediately below it, before the normal category buckets.
    if (self.groupByCategory) return (NSInteger)self.visibleCategories.count + 2;
    return 3;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    if (section == 0) return MAX((NSInteger)self.favoritePackages.count, 1);
    if (section == 1) return MAX((NSInteger)self.reworkedPackages.count, 1);
    if (self.groupByCategory) {
        NSString *cat = self.visibleCategories[section - 2];
        return (NSInteger)self.packagesByCategory[cat].count;
    }
    return (NSInteger)self.flatPackages.count;
}

- (CGFloat)tableView:(UITableView *)tableView heightForHeaderInSection:(NSInteger)section
{
    // Keep the Favorites and Reworked headers compact above the package rows.
    if (section <= 1) return 26.0;
    return UITableViewAutomaticDimension;
}

- (UIView *)tableView:(UITableView *)tableView viewForHeaderInSection:(NSInteger)section
{
    // Use a plain view so UIKit does not render a second system title on top
    // of the compact section title.
    if (section > 1) return nil;
    NSString *title = [self tableView:tableView titleForHeaderInSection:section];
    if (!title.length) return nil;

    UIView *hdr = [[UIView alloc] init];
    UILabel *lbl = [[UILabel alloc] init];
    // Match the system's plain-style header look: uppercase, footnote weight,
    // secondary label color. Tracking is tightened a touch for the small caps.
    NSDictionary *attrs = @{
        NSFontAttributeName: [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold],
        NSForegroundColorAttributeName: UIColor.secondaryLabelColor,
        NSKernAttributeName: @(0.4),
    };
    lbl.attributedText = [[NSAttributedString alloc] initWithString:title.uppercaseString attributes:attrs];
    lbl.translatesAutoresizingMaskIntoConstraints = NO;
    [hdr addSubview:lbl];
    [NSLayoutConstraint activateConstraints:@[
        [lbl.leadingAnchor  constraintEqualToAnchor:hdr.layoutMarginsGuide.leadingAnchor],
        [lbl.trailingAnchor constraintEqualToAnchor:hdr.layoutMarginsGuide.trailingAnchor],
        [lbl.bottomAnchor   constraintEqualToAnchor:hdr.bottomAnchor constant:-4.0],
    ]];
    return hdr;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    if (section == 0) return @"Favorites";
    if (section == 1) return @"Reworked";
    if (self.groupByCategory) return self.visibleCategories[section - 2];
    return @"All Tweaks";
}

- (Package *)packageAtIndexPath:(NSIndexPath *)indexPath
{
    if (indexPath.section == 0) {
        if (self.favoritePackages.count == 0) return nil;
        return self.favoritePackages[indexPath.row];
    }
    if (indexPath.section == 1) {
        if (self.reworkedPackages.count == 0) return nil;
        return self.reworkedPackages[indexPath.row];
    }
    if (self.groupByCategory) {
        NSString *cat = self.visibleCategories[indexPath.section - 2];
        return self.packagesByCategory[cat][indexPath.row];
    }
    return self.flatPackages[indexPath.row];
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:kPackageCellID];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:kPackageCellID];
    }

    Package *pkg = [self packageAtIndexPath:indexPath];
    if (!pkg) {
        BOOL reworkedSection = indexPath.section == 1;
        BOOL filteringFavorites = !reworkedSection && self.searchText.length > 0 &&
                                  PackageFavoriteIdentifiers().count > 0;
        UIListContentConfiguration *empty = [UIListContentConfiguration subtitleCellConfiguration];
        empty.image = [UIImage systemImageNamed:reworkedSection ? @"wand.and.stars" : @"star"];
        empty.imageProperties.tintColor = UIColor.tertiaryLabelColor;
        if (reworkedSection) {
            empty.text = self.searchText.length > 0
                ? @"No matching reworked tweaks" : @"No reworked tweaks";
            empty.secondaryText = self.searchText.length > 0
                ? @"Try another search." : @"SnowBoard Remix and Font Changer appear here.";
        } else {
            empty.text = filteringFavorites ? @"No matching favorites" : @"No favorites yet";
            empty.secondaryText = filteringFavorites
                ? @"Try another search."
                : @"Tap the star on any tweak to add it here.";
        }
        empty.textProperties.color = UIColor.secondaryLabelColor;
        empty.secondaryTextProperties.color = UIColor.tertiaryLabelColor;
        cell.contentConfiguration = empty;
        cell.accessoryView = nil;
        cell.accessoryType = UITableViewCellAccessoryNone;
        cell.selectionStyle = UITableViewCellSelectionStyleNone;
        return cell;
    }
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;

    // UIListContentConfiguration with a fixed reservedLayoutSize so every
    // SF Symbol occupies the same horizontal slot regardless of its intrinsic
    // aspect ratio. Without this, wider glyphs (apps.iphone, antenna.*) push
    // their text further right than narrower ones (thermometer, sun.max).
    UIListContentConfiguration *config = [UIListContentConfiguration subtitleCellConfiguration];
    config.image = [UIImage systemImageNamed:pkg.symbolName];
    config.imageProperties.preferredSymbolConfiguration =
        [UIImageSymbolConfiguration configurationWithPointSize:22.0 weight:UIImageSymbolWeightRegular];
    UIColor *mainColor = pkg.isInstallDisabled ? UIColor.secondaryLabelColor : self.view.tintColor;
    config.imageProperties.tintColor       = mainColor;
    config.imageProperties.reservedLayoutSize = CGSizeMake(34.0, 28.0);
    config.imageProperties.maximumSize     = CGSizeMake(28.0, 28.0);
    config.imageToTextPadding              = 14.0;
    config.text = pkg.name;
    config.textProperties.font = [UIFont systemFontOfSize:17.0 weight:UIFontWeightSemibold];
    if (pkg.isInstallDisabled) config.textProperties.color = UIColor.secondaryLabelColor;
    config.secondaryText = pkg.shortDescription;
    config.secondaryTextProperties.color = pkg.isInstallDisabled ? UIColor.tertiaryLabelColor : UIColor.secondaryLabelColor;
    config.secondaryTextProperties.numberOfLines = 2;
    config.textToSecondaryTextVerticalPadding = 3.0;
    NSDirectionalEdgeInsets m = config.directionalLayoutMargins;
    m.top    = 14.0;
    m.bottom = 14.0;
    config.directionalLayoutMargins = m;
    cell.contentConfiguration = config;

    cell.accessoryView = [self combinedAccessoryViewForPackage:pkg];
    cell.accessoryType = UITableViewCellAccessoryNone;

    return cell;
}

- (UIView *)combinedAccessoryViewForPackage:(Package *)pkg
{
    UIView *status = [self accessoryViewForPackage:pkg];
    if (status) {
        status.translatesAutoresizingMaskIntoConstraints = NO;
        [NSLayoutConstraint activateConstraints:@[
            [status.widthAnchor constraintEqualToConstant:CGRectGetWidth(status.frame)],
            [status.heightAnchor constraintEqualToConstant:CGRectGetHeight(status.frame)],
        ]];
    }

    BOOL favorite = PackageIdentifierIsFavorite(pkg.identifier);
    UIButton *star = [UIButton buttonWithType:UIButtonTypeSystem];
    star.translatesAutoresizingMaskIntoConstraints = NO;
    [star setImage:[UIImage systemImageNamed:favorite ? @"star.fill" : @"star"]
          forState:UIControlStateNormal];
    star.tintColor = favorite ? UIColor.systemYellowColor : UIColor.secondaryLabelColor;
    star.accessibilityLabel = favorite ? @"Remove from Favorites" : @"Add to Favorites";
    star.accessibilityHint = pkg.name;
    [NSLayoutConstraint activateConstraints:@[
        [star.widthAnchor constraintEqualToConstant:44.0],
        [star.heightAnchor constraintEqualToConstant:44.0],
    ]];

    NSString *identifier = [pkg.identifier copy];
    [star addAction:[UIAction actionWithHandler:^(__unused UIAction *action) {
        PackageSetIdentifierFavorite(identifier,
                                     !PackageIdentifierIsFavorite(identifier));
    }] forControlEvents:UIControlEventTouchUpInside];

    UIImageView *chevron = [[UIImageView alloc]
        initWithImage:[UIImage systemImageNamed:@"chevron.right"]];
    chevron.translatesAutoresizingMaskIntoConstraints = NO;
    chevron.tintColor = UIColor.tertiaryLabelColor;
    chevron.contentMode = UIViewContentModeScaleAspectFit;
    [NSLayoutConstraint activateConstraints:@[
        [chevron.widthAnchor constraintEqualToConstant:8.0],
        [chevron.heightAnchor constraintEqualToConstant:14.0],
    ]];

    NSMutableArray<UIView *> *items = [NSMutableArray array];
    if (status) [items addObject:status];
    [items addObject:star];
    [items addObject:chevron];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:items];
    stack.axis = UILayoutConstraintAxisHorizontal;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 5.0;
    CGSize size = [stack systemLayoutSizeFittingSize:UILayoutFittingCompressedSize];
    stack.frame = CGRectMake(0, 0, ceil(size.width), MAX(44.0, ceil(size.height)));
    return stack;
}

- (UIView *)accessoryViewForPackage:(Package *)pkg
{
    PackageQueueIntent intent = [[PackageQueue sharedQueue] intentForPackage:pkg];
    if (pkg.kind == PackageInstallKindDirectTool) {
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (pkg.kind == PackageInstallKindOTA) {
        if (intent != PackageQueueIntentNone) {
            NSString *text = (intent == PackageQueueIntentInstall) ? @"DISABLE PENDING" : @"ENABLE PENDING";
            UIColor *color = self.view.tintColor;
            return [self pillWithText:text
                           background:[color colorWithAlphaComponent:0.18]
                            textColor:color];
        }
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (pkg.kind == PackageInstallKindNanoRegistry) {
        if (intent != PackageQueueIntentNone) {
            NSString *text = (intent == PackageQueueIntentInstall) ? @"APPLY PENDING" : @"REMOVE PENDING";
            UIColor *color = self.view.tintColor;
            return [self pillWithText:text
                           background:[color colorWithAlphaComponent:0.18]
                            textColor:color];
        }
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (pkg.kind == PackageInstallKindCallRecordingSound) {
        if (intent != PackageQueueIntentNone) {
            NSString *text = (intent == PackageQueueIntentInstall) ? @"SILENCE PENDING" : @"RESTORE PENDING";
            UIColor *color = self.view.tintColor;
            return [self pillWithText:text
                           background:[color colorWithAlphaComponent:0.18]
                            textColor:color];
        }
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (pkg.kind == PackageInstallKindHideHomeBar) {
        if (intent != PackageQueueIntentNone) {
            NSString *text = (intent == PackageQueueIntentInstall) ? @"HIDE PENDING" : @"RESTORE PENDING";
            UIColor *color = self.view.tintColor;
            return [self pillWithText:text
                           background:[color colorWithAlphaComponent:0.18]
                            textColor:color];
        }
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (pkg.kind == PackageInstallKindFontChanger) {
        if (intent != PackageQueueIntentNone) {
            NSString *text = (intent == PackageQueueIntentInstall) ? @"APPLY PENDING" : @"RESTORE PENDING";
            UIColor *color = self.view.tintColor;
            return [self pillWithText:text
                           background:[color colorWithAlphaComponent:0.18]
                            textColor:color];
        }
        return [self pillWithText:@"MANUAL"
                       background:[UIColor.secondaryLabelColor colorWithAlphaComponent:0.14]
                        textColor:UIColor.secondaryLabelColor];
    }
    if (intent != PackageQueueIntentNone) {
        NSString *text = (intent == PackageQueueIntentInstall) ? @"WILL ACTIVATE" : @"WILL DEACTIVATE";
        UIColor *color = self.view.tintColor;
        return [self pillWithText:text
                       background:[color colorWithAlphaComponent:0.18]
                        textColor:color];
    }
    if (pkg.isInstalled) {
        return [self pillWithText:@"INSTALLED"
                       background:[UIColor colorWithRed:0.16 green:0.55 blue:0.32 alpha:0.18]
                        textColor:[UIColor systemGreenColor]];
    }
    if (pkg.isInstallDisabled) {
        return [self pillWithText:@"DISABLED"
                       background:[[UIColor systemRedColor] colorWithAlphaComponent:0.16]
                        textColor:[UIColor systemRedColor]];
    }
    if (pkg.creatorOnly) {
        return [self pillWithText:@"IN DEV"
                       background:[[UIColor systemPurpleColor] colorWithAlphaComponent:0.16]
                        textColor:[UIColor systemPurpleColor]];
    }
    if (pkg.experimental) {
        return [self pillWithText:@"EXPERIMENTAL"
                       background:[[UIColor systemRedColor] colorWithAlphaComponent:0.18]
                        textColor:[UIColor systemRedColor]];
    }
    if ([pkg.category caseInsensitiveCompare:@"Beta"] == NSOrderedSame) {
        return [self pillWithText:@"BETA"
                       background:[[UIColor systemPurpleColor] colorWithAlphaComponent:0.18]
                        textColor:[UIColor systemPurpleColor]];
    }
    if (pkg.isNew) {
        return [self pillWithText:@"NEW"
                       background:[UIColor colorWithRed:0.95 green:0.55 blue:0.05 alpha:0.18]
                        textColor:[UIColor systemOrangeColor]];
    }
    return nil;
}

- (UIView *)pillWithText:(NSString *)text background:(UIColor *)bg textColor:(UIColor *)fg
{
    UILabel *pill = [[UILabel alloc] init];
    pill.text = text;
    pill.font = [UIFont systemFontOfSize:11.0 weight:UIFontWeightHeavy];
    pill.textColor = fg;
    pill.backgroundColor = bg;
    pill.textAlignment = NSTextAlignmentCenter;
    [pill sizeToFit];

    CGRect frame = pill.frame;
    frame.size.width  += 14.0;
    frame.size.height = 22.0;
    pill.frame = frame;

    pill.layer.cornerRadius = frame.size.height / 2.0;
    pill.layer.cornerCurve = kCACornerCurveContinuous;
    pill.layer.masksToBounds = YES;
    return pill;
}

#pragma mark - Delegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    Package *pkg = [self packageAtIndexPath:indexPath];
    if (!pkg) return;
    PackageDetailViewController *detail = [[PackageDetailViewController alloc] initWithPackage:pkg];
    [self.navigationController pushViewController:detail animated:YES];
}

- (UISwipeActionsConfiguration *)tableView:(UITableView *)tableView
    trailingSwipeActionsConfigurationForRowAtIndexPath:(NSIndexPath *)indexPath
{
    Package *pkg = [self packageAtIndexPath:indexPath];
    if (!pkg) return nil;
    PackageQueue *q = [PackageQueue sharedQueue];
    PackageQueueIntent intent = [q intentForPackage:pkg];
    if (pkg.kind == PackageInstallKindDirectTool) {
        UIContextualAction *open = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Open"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            done(YES);
            [self navigateToSettingsSectionForPackage:pkg];
        }];
        open.backgroundColor = self.view.tintColor;
        open.image = [UIImage systemImageNamed:@"slider.horizontal.3"];
        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[open]];
        cfg.performsFirstActionWithFullSwipe = YES;
        return cfg;
    }
    if (pkg.isInstallDisabled && !pkg.isInstalled && intent == PackageQueueIntentNone) return nil;

    if (pkg.kind == PackageInstallKindOTA && intent == PackageQueueIntentNone) {
        UIContextualAction *disable = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Disable"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentInstall forPackage:pkg];
            done(YES);
        }];
        disable.image = [UIImage systemImageNamed:@"icloud.slash"];

        UIContextualAction *enable = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Enable"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentUninstall forPackage:pkg];
            done(YES);
        }];
        enable.backgroundColor = UIColor.systemGreenColor;
        enable.image = [UIImage systemImageNamed:@"icloud"];

        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[disable, enable]];
        cfg.performsFirstActionWithFullSwipe = NO;
        return cfg;
    }

    if (pkg.kind == PackageInstallKindNanoRegistry && intent == PackageQueueIntentNone) {
        UIContextualAction *apply = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Apply"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentInstall forPackage:pkg];
            done(YES);
        }];
        apply.backgroundColor = self.view.tintColor;
        apply.image = [UIImage systemImageNamed:@"applewatch.radiowaves.left.and.right"];

        UIContextualAction *remove = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Remove"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentUninstall forPackage:pkg];
            done(YES);
        }];
        remove.image = [UIImage systemImageNamed:@"xmark.circle"];

        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[apply, remove]];
        cfg.performsFirstActionWithFullSwipe = NO;
        return cfg;
    }

    if (pkg.kind == PackageInstallKindCallRecordingSound && intent == PackageQueueIntentNone) {
        UIContextualAction *silence = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Silence"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            done(YES);
            [PackageDetailViewController
                presentCallRecordingDisclosureIfNeededFromViewController:self
                                                          confirmHandler:^{
                if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) return;
                [q queueIntent:PackageQueueIntentInstall forPackage:pkg];
            }];
        }];
        silence.image = [UIImage systemImageNamed:@"speaker.slash.fill"];

        UIContextualAction *restore = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Restore"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentUninstall forPackage:pkg];
            done(YES);
        }];
        restore.backgroundColor = UIColor.systemGreenColor;
        restore.image = [UIImage systemImageNamed:@"speaker.wave.2.fill"];

        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[silence, restore]];
        cfg.performsFirstActionWithFullSwipe = NO;
        return cfg;
    }

    if (pkg.kind == PackageInstallKindHideHomeBar && intent == PackageQueueIntentNone) {
        UIContextualAction *hide = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Hide"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentInstall forPackage:pkg];
            done(YES);
        }];
        hide.image = [UIImage systemImageNamed:@"line.3.horizontal"];

        UIContextualAction *restore = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Restore"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentUninstall forPackage:pkg];
            done(YES);
        }];
        restore.backgroundColor = UIColor.systemGreenColor;
        restore.image = [UIImage systemImageNamed:@"arrow.clockwise"];

        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[hide, restore]];
        cfg.performsFirstActionWithFullSwipe = NO;
        return cfg;
    }

    if (pkg.kind == PackageInstallKindFontChanger && intent == PackageQueueIntentNone) {
        UIContextualAction *apply = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleNormal
                                title:@"Apply"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self packageNeedsFontBeforeInstall:pkg]) {
                done(YES);
                [self navigateToSettingsSectionForPackage:pkg];
                return;
            }
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentInstall forPackage:pkg];
            done(YES);
        }];
        apply.backgroundColor = self.view.tintColor;
        apply.image = [UIImage systemImageNamed:@"textformat"];

        UIContextualAction *restore = [UIContextualAction
            contextualActionWithStyle:UIContextualActionStyleDestructive
                                title:@"Restore"
                              handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
            if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
                done(YES);
                return;
            }
            [q queueIntent:PackageQueueIntentUninstall forPackage:pkg];
            done(YES);
        }];
        restore.image = [UIImage systemImageNamed:@"arrow.clockwise"];

        UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[apply, restore]];
        cfg.performsFirstActionWithFullSwipe = NO;
        return cfg;
    }

    NSString *title;
    UIColor *color;
    NSString *symbol;
    if (intent != PackageQueueIntentNone) {
        title  = @"Cancel";
        color  = [UIColor systemGrayColor];
        symbol = @"xmark.circle";
    } else if (pkg.isInstalled) {
        title  = @"Deactivate";
        color  = [UIColor systemRedColor];
        symbol = @"power";
    } else if ([self packageNeedsThemeBeforeInstall:pkg]) {
        title  = @"Select Theme";
        color  = self.view.tintColor;
        symbol = @"paintpalette";
    } else if ([self packageNeedsLiveWPVideoBeforeInstall:pkg]) {
        title  = @"Select Video";
        color  = self.view.tintColor;
        symbol = @"photo.badge.plus";
    } else if ([self packageNeedsFontBeforeInstall:pkg]) {
        title  = @"Import Font";
        color  = self.view.tintColor;
        symbol = @"textformat";
    } else {
        title  = @"Activate";
        color  = self.view.tintColor;
        symbol = @"play.circle";
    }

    UIContextualAction *action = [UIContextualAction
        contextualActionWithStyle:UIContextualActionStyleNormal
                            title:title
                          handler:^(UIContextualAction *a, UIView *v, void (^done)(BOOL)) {
        BOOL isInstall = (intent == PackageQueueIntentNone && !pkg.isInstalled);
        BOOL isUninstall = (intent == PackageQueueIntentNone && pkg.isInstalled);
        if (NO && isInstall && pkg.settingsSection != NSIntegerMax) {
            done(YES);
            [self presentConfigureAlertForPackage:pkg];
            return;
        }
        if (isInstall && [self packageNeedsThemeBeforeInstall:pkg]) {
            done(YES);
            [self presentThemeRequiredAlertForPackage:pkg];
            return;
        }
        if (isInstall && [self packageNeedsLiveWPVideoBeforeInstall:pkg]) {
            done(YES);
            [self navigateToSettingsSectionForPackage:pkg];
            return;
        }
        if (isInstall && [self packageNeedsFontBeforeInstall:pkg]) {
            done(YES);
            [self navigateToSettingsSectionForPackage:pkg];
            return;
        }
        if (isInstall && [self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) {
            done(YES);
            return;
        }
        if (isUninstall && [self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentUninstall]) {
            done(YES);
            return;
        }
        [q toggleForPackage:pkg];
        done(YES);
    }];
    action.backgroundColor = color;
    action.image = [UIImage systemImageNamed:symbol];

    UISwipeActionsConfiguration *cfg = [UISwipeActionsConfiguration configurationWithActions:@[action]];
    cfg.performsFirstActionWithFullSwipe = YES;
    return cfg;
}

- (void)presentThemeRequiredAlertForPackage:(Package *)pkg
{
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Select a Theme"
                                                                   message:@"Icon themes need a selected theme before they can be activated. Choose iOS 6 Theme or import a custom theme first."
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Open Theme Settings"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *_) {
        [self navigateToSettingsSectionForPackage:pkg];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                             style:UIAlertActionStyleCancel
                                           handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)navigateToSettingsSectionForPackage:(Package *)pkg
{
    UITabBarController *tab = self.tabBarController;
    NSUInteger settingsIndex = NSNotFound;
    UINavigationController *settingsNav = nil;
    for (NSUInteger i = 0; i < tab.viewControllers.count; i++) {
        UIViewController *vc = tab.viewControllers[i];
        if ([vc.tabBarItem.title isEqualToString:@"Settings"]) {
            settingsIndex = i;
            if ([vc isKindOfClass:UINavigationController.class]) {
                settingsNav = (UINavigationController *)vc;
            }
            break;
        }
    }
    if (settingsIndex == NSNotFound || !settingsNav) return;

    [settingsNav popToRootViewControllerAnimated:NO];
    SettingsViewController *bundle = [[SettingsViewController alloc] initWithUnderlyingSection:pkg.settingsSection
                                                                                   bundleTitle:pkg.name];
    bundle.installerReturnPackageName = pkg.name;
    [settingsNav pushViewController:bundle animated:NO];
    tab.selectedIndex = settingsIndex;
}

- (void)presentConfigureAlertForPackage:(Package *)pkg
{
    NSString *msg = [NSString stringWithFormat:
        @"%@ has configurable options. Set them up first so the tweak applies with your preferences on the first activation.",
        pkg.name];
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Customize Before Activating?"
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Configure First"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *_) {
        PackageDetailViewController *detail = [[PackageDetailViewController alloc] initWithPackage:pkg];
        [self.navigationController pushViewController:detail animated:YES];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Activate Anyway"
                                             style:UIAlertActionStyleDefault
                                           handler:^(UIAlertAction *_) {
        if ([self presentQueueConflictIfNeededForPackage:pkg intent:PackageQueueIntentInstall]) return;
        [[PackageQueue sharedQueue] toggleForPackage:pkg];
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
                                             style:UIAlertActionStyleCancel
                                           handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
