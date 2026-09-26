//
//  CNDDockAppPickerViewController.m
//  Cyanide
//

#import "CNDDockAppPickerViewController.h"
#import "CNDDockAppCatalog.h"

typedef NS_ENUM(NSInteger, CNDDockAppPickerSection) {
    CNDDockAppPickerSectionSelected = 0,
    CNDDockAppPickerSectionApplications,
    CNDDockAppPickerSectionCount,
};

static NSString * const CNDDockSelectedCellIdentifier = @"CNDDockSelectedCell";
static NSString * const CNDDockApplicationCellIdentifier = @"CNDDockApplicationCell";
static NSString * const CNDDockPlaceholderCellIdentifier = @"CNDDockPlaceholderCell";

@interface CNDDockAppPickerViewController () <UISearchResultsUpdating>

@property (nonatomic, assign, readwrite) NSUInteger selectionCapacity;
@property (nonatomic, strong) NSMutableArray<NSString *> *mutableSelectedBundleIdentifiers;
@property (nonatomic, copy) NSArray<CNDDockApplication *> *applications;
@property (nonatomic, copy) NSArray<CNDDockApplication *> *filteredApplications;
@property (nonatomic, copy) NSDictionary<NSString *, CNDDockApplication *> *applicationsByIdentifier;
@property (nonatomic, strong) UISearchController *searchController;
@property (nonatomic, copy, nullable) CNDDockAppPickerCompletion completion;
@property (nonatomic, assign, getter=isLoadingApplications) BOOL loadingApplications;
@property (nonatomic, strong) UIBarButtonItem *doneButtonItem;

@end


@implementation CNDDockAppPickerViewController

- (instancetype)initWithSelectedBundleIdentifiers:(NSArray<NSString *> *)selectedBundleIdentifiers
                                          capacity:(NSUInteger)capacity
                                        completion:(CNDDockAppPickerCompletion)completion
{
    self = [super initWithStyle:UITableViewStyleInsetGrouped];
    if (!self) return nil;

    _selectionCapacity = MIN(capacity, (NSUInteger)3);
    _completion = [completion copy];
    _applications = @[];
    _filteredApplications = @[];
    _applicationsByIdentifier = @{};
    _loadingApplications = YES;

    NSMutableArray<NSString *> *ordered = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (id value in selectedBundleIdentifiers ?: @[]) {
        if (![value isKindOfClass:NSString.class]) continue;
        NSString *identifier = [(NSString *)value
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (identifier.length == 0 || [seen containsObject:identifier]) continue;
        [seen addObject:identifier];
        [ordered addObject:identifier];
    }
    _mutableSelectedBundleIdentifiers = ordered;
    return self;
}

- (NSArray<NSString *> *)selectedBundleIdentifiers
{
    return [self.mutableSelectedBundleIdentifiers copy];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.title = @"Dock Autofill";
    self.navigationItem.largeTitleDisplayMode = UINavigationItemLargeTitleDisplayModeNever;
    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                     target:self
                                                     action:@selector(cancelTapped:)];
    self.doneButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemDone
                                                     target:self
                                                     action:@selector(doneTapped:)];
    self.navigationItem.rightBarButtonItem = self.doneButtonItem;

    self.tableView.rowHeight = UITableViewAutomaticDimension;
    self.tableView.estimatedRowHeight = 58.0;
    self.tableView.keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
    if (@available(iOS 15.0, *)) self.tableView.sectionHeaderTopPadding = 4.0;

    self.searchController = [[UISearchController alloc] initWithSearchResultsController:nil];
    self.searchController.searchResultsUpdater = self;
    self.searchController.obscuresBackgroundDuringPresentation = NO;
    self.searchController.searchBar.placeholder = @"Search apps or bundle IDs";
    self.navigationItem.searchController = self.searchController;
    self.navigationItem.hidesSearchBarWhenScrolling = NO;
    self.definesPresentationContext = YES;

    [self updateCapacityUI];
    [self loadApplicationCatalog];
}

- (void)loadApplicationCatalog
{
    self.loadingApplications = YES;
    __weak typeof(self) weakSelf = self;
    [CNDDockAppCatalog loadInstalledApplicationsWithCompletion:^(NSArray<CNDDockApplication *> *applications) {
        __strong typeof(weakSelf) self = weakSelf;
        if (!self) return;

        self.loadingApplications = NO;
        self.applications = applications ?: @[];
        NSMutableDictionary<NSString *, CNDDockApplication *> *byIdentifier =
            [NSMutableDictionary dictionaryWithCapacity:self.applications.count];
        for (CNDDockApplication *application in self.applications) {
            byIdentifier[application.bundleIdentifier] = application;
        }
        self.applicationsByIdentifier = byIdentifier;
        [self rebuildFilteredApplications];
    }];
}

- (void)rebuildFilteredApplications
{
    NSString *query = [self.searchController.searchBar.text ?: @""
        stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSArray<NSString *> *rawTokens = [query componentsSeparatedByCharactersInSet:
        NSCharacterSet.whitespaceAndNewlineCharacterSet];
    NSMutableArray<NSString *> *tokens = [NSMutableArray array];
    for (NSString *token in rawTokens) {
        if (token.length > 0) [tokens addObject:token];
    }

    if (tokens.count == 0) {
        self.filteredApplications = self.applications;
    } else {
        self.filteredApplications = [self.applications
            filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(CNDDockApplication *application,
                                                                               NSDictionary *bindings) {
            (void)bindings;
            NSString *haystack = [NSString stringWithFormat:@"%@\n%@",
                                   application.displayName,
                                   application.bundleIdentifier];
            for (NSString *token in tokens) {
                if ([haystack rangeOfString:token
                                    options:(NSCaseInsensitiveSearch |
                                             NSDiacriticInsensitiveSearch)].location == NSNotFound) {
                    return NO;
                }
            }
            return YES;
        }]];
    }
    [self.tableView reloadData];
}

- (void)updateCapacityUI
{
    NSUInteger selectedCount = self.mutableSelectedBundleIdentifiers.count;
    self.doneButtonItem.enabled = selectedCount <= self.selectionCapacity;

    if (self.selectionCapacity == 0) {
        self.navigationItem.prompt = selectedCount == 0
            ? @"No automatic dock slots are available"
            : @"Remove saved apps to continue";
    } else if (selectedCount > self.selectionCapacity) {
        self.navigationItem.prompt = @"Remove apps until the selection fits";
    } else {
        self.navigationItem.prompt =
            [NSString stringWithFormat:@"Choose up to %lu app%@",
             (unsigned long)self.selectionCapacity,
             self.selectionCapacity == 1 ? @"" : @"s"];
    }
}

- (void)cancelTapped:(id)sender
{
    (void)sender;
    self.completion = nil;
    [self closePicker];
}

- (void)doneTapped:(id)sender
{
    (void)sender;
    if (self.mutableSelectedBundleIdentifiers.count > self.selectionCapacity) return;

    CNDDockAppPickerCompletion completion = self.completion;
    self.completion = nil;
    if (completion) completion(self.selectedBundleIdentifiers);
    [self closePicker];
}

- (void)closePicker
{
    UIViewController *container = self.navigationController ?: self;
    if (container.presentingViewController) {
        [container dismissViewControllerAnimated:YES completion:nil];
    } else if (self.navigationController.viewControllers.firstObject != self) {
        [self.navigationController popViewControllerAnimated:YES];
    }
}

- (NSUInteger)selectedIndexForBundleIdentifier:(NSString *)bundleIdentifier
{
    return [self.mutableSelectedBundleIdentifiers indexOfObject:bundleIdentifier];
}

- (void)removeBundleIdentifier:(NSString *)bundleIdentifier
{
    NSUInteger index = [self selectedIndexForBundleIdentifier:bundleIdentifier];
    if (index == NSNotFound) return;
    [self.mutableSelectedBundleIdentifiers removeObjectAtIndex:index];
    [self updateCapacityUI];
    [self.tableView reloadData];
}

- (void)addBundleIdentifier:(NSString *)bundleIdentifier
{
    if (bundleIdentifier.length == 0) return;
    if ([self selectedIndexForBundleIdentifier:bundleIdentifier] != NSNotFound) {
        [self removeBundleIdentifier:bundleIdentifier];
        return;
    }

    if (self.mutableSelectedBundleIdentifiers.count >= self.selectionCapacity) {
        [self presentCapacityAlert];
        return;
    }

    [self.mutableSelectedBundleIdentifiers addObject:bundleIdentifier];
    [self updateCapacityUI];
    [self.tableView reloadData];
}

- (void)presentCapacityAlert
{
    NSString *message = self.selectionCapacity == 0
        ? @"The current dock size has no automatic slots available."
        : [NSString stringWithFormat:@"Remove one selected app before choosing another. This dock has %lu automatic slot%@.",
           (unsigned long)self.selectionCapacity,
           self.selectionCapacity == 1 ? @"" : @"s"];
    UIAlertController *alert =
        [UIAlertController alertControllerWithTitle:@"Dock Selection Full"
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                              style:UIAlertActionStyleDefault
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (UILabel *)orderBadgeForIndex:(NSUInteger)index
{
    UILabel *badge = [[UILabel alloc] initWithFrame:CGRectMake(0, 0, 34, 28)];
    badge.text = [NSString stringWithFormat:@"#%lu", (unsigned long)(index + 1)];
    badge.textAlignment = NSTextAlignmentCenter;
    badge.font = [UIFont monospacedDigitSystemFontOfSize:15.0 weight:UIFontWeightSemibold];
    badge.textColor = self.view.tintColor;
    badge.accessibilityLabel = [NSString stringWithFormat:@"Dock position %lu",
                                (unsigned long)(index + 1)];
    return badge;
}

#pragma mark - UISearchResultsUpdating

- (void)updateSearchResultsForSearchController:(UISearchController *)searchController
{
    (void)searchController;
    [self rebuildFilteredApplications];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView
{
    (void)tableView;
    return CNDDockAppPickerSectionCount;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section
{
    (void)tableView;
    if (section == CNDDockAppPickerSectionSelected) {
        return MAX((NSInteger)self.mutableSelectedBundleIdentifiers.count, 1);
    }
    if (self.loadingApplications || self.filteredApplications.count == 0) return 1;
    return self.filteredApplications.count;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section
{
    (void)tableView;
    if (section == CNDDockAppPickerSectionSelected) {
        return [NSString stringWithFormat:@"Dock Order — %lu of %lu",
                (unsigned long)self.mutableSelectedBundleIdentifiers.count,
                (unsigned long)self.selectionCapacity];
    }
    if (self.loadingApplications) return @"Applications";
    return [NSString stringWithFormat:@"Applications — %lu",
            (unsigned long)self.filteredApplications.count];
}

- (NSString *)tableView:(UITableView *)tableView titleForFooterInSection:(NSInteger)section
{
    (void)tableView;
    if (section != CNDDockAppPickerSectionSelected) return nil;

    NSUInteger selectedCount = self.mutableSelectedBundleIdentifiers.count;
    if (selectedCount > self.selectionCapacity) {
        return [NSString stringWithFormat:@"Remove %lu app%@ before saving. Unavailable saved apps remain visible here so they can be removed.",
                (unsigned long)(selectedCount - self.selectionCapacity),
                selectedCount - self.selectionCapacity == 1 ? @"" : @"s"];
    }
    return @"Apps are added in this order. Tap a selected app to remove it; select it again to move it to the end.";
}

- (UITableViewCell *)placeholderCellWithText:(NSString *)text detail:(nullable NSString *)detail
{
    UITableViewCell *cell = [self.tableView dequeueReusableCellWithIdentifier:CNDDockPlaceholderCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:CNDDockPlaceholderCellIdentifier];
    }
    cell.textLabel.text = text;
    cell.textLabel.textColor = UIColor.secondaryLabelColor;
    cell.detailTextLabel.text = detail;
    cell.detailTextLabel.textColor = UIColor.tertiaryLabelColor;
    cell.imageView.image = nil;
    cell.accessoryType = UITableViewCellAccessoryNone;
    cell.accessoryView = nil;
    cell.selectionStyle = UITableViewCellSelectionStyleNone;
    return cell;
}

- (UITableViewCell *)tableView:(UITableView *)tableView
         cellForRowAtIndexPath:(NSIndexPath *)indexPath
{
    if (indexPath.section == CNDDockAppPickerSectionSelected) {
        if (self.mutableSelectedBundleIdentifiers.count == 0) {
            return [self placeholderCellWithText:@"No apps selected"
                                          detail:@"Choose apps below to set their dock order."];
        }

        UITableViewCell *cell =
            [tableView dequeueReusableCellWithIdentifier:CNDDockSelectedCellIdentifier];
        if (!cell) {
            cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                          reuseIdentifier:CNDDockSelectedCellIdentifier];
        }

        NSString *bundleIdentifier = self.mutableSelectedBundleIdentifiers[indexPath.row];
        CNDDockApplication *application = self.applicationsByIdentifier[bundleIdentifier];
        BOOL missing = !self.loadingApplications && !application;
        cell.textLabel.text = application.displayName ?: (missing ? @"Unavailable App" : bundleIdentifier);
        cell.textLabel.textColor = missing ? UIColor.secondaryLabelColor : UIColor.labelColor;
        cell.detailTextLabel.text = missing
            ? [NSString stringWithFormat:@"Not currently installed • %@", bundleIdentifier]
            : bundleIdentifier;
        cell.detailTextLabel.textColor = missing ? UIColor.systemOrangeColor : UIColor.secondaryLabelColor;
        cell.imageView.image = [UIImage systemImageNamed:missing ? @"questionmark.app.dashed" : @"app.fill"];
        cell.imageView.tintColor = missing ? UIColor.systemOrangeColor : self.view.tintColor;
        cell.accessoryType = UITableViewCellAccessoryNone;
        cell.accessoryView = [self orderBadgeForIndex:indexPath.row];
        cell.selectionStyle = UITableViewCellSelectionStyleDefault;
        cell.accessibilityHint = @"Removes this app from dock autofill.";
        return cell;
    }

    if (self.loadingApplications) {
        return [self placeholderCellWithText:@"Loading Applications…" detail:nil];
    }
    if (self.filteredApplications.count == 0) {
        return [self placeholderCellWithText:@"No Applications Found"
                                      detail:@"Run SnowBoard Remix successfully once, then reopen this list."];
    }

    UITableViewCell *cell =
        [tableView dequeueReusableCellWithIdentifier:CNDDockApplicationCellIdentifier];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle
                                      reuseIdentifier:CNDDockApplicationCellIdentifier];
    }
    CNDDockApplication *application = self.filteredApplications[indexPath.row];
    NSUInteger selectedIndex = [self selectedIndexForBundleIdentifier:application.bundleIdentifier];
    BOOL selected = selectedIndex != NSNotFound;

    cell.textLabel.text = application.displayName;
    cell.textLabel.textColor = UIColor.labelColor;
    cell.detailTextLabel.text = selected
        ? [NSString stringWithFormat:@"%@ • Selected #%lu",
           application.bundleIdentifier, (unsigned long)(selectedIndex + 1)]
        : application.bundleIdentifier;
    cell.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    cell.imageView.image = [UIImage systemImageNamed:application.isSystemApplication
                                                    ? @"gearshape.app.fill"
                                                    : @"app.fill"];
    cell.imageView.tintColor = application.isSystemApplication
        ? UIColor.secondaryLabelColor : self.view.tintColor;
    cell.accessoryType = selected ? UITableViewCellAccessoryCheckmark : UITableViewCellAccessoryNone;
    cell.accessoryView = nil;
    cell.selectionStyle = UITableViewCellSelectionStyleDefault;
    cell.accessibilityHint = selected
        ? @"Removes this app from dock autofill."
        : @"Adds this app at the end of the dock order.";
    return cell;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath
{
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.section == CNDDockAppPickerSectionSelected) {
        if (self.mutableSelectedBundleIdentifiers.count == 0) return;
        NSString *bundleIdentifier = self.mutableSelectedBundleIdentifiers[indexPath.row];
        [self removeBundleIdentifier:bundleIdentifier];
        return;
    }

    if (self.loadingApplications || self.filteredApplications.count == 0) return;
    CNDDockApplication *application = self.filteredApplications[indexPath.row];
    [self addBundleIdentifier:application.bundleIdentifier];
}

@end
