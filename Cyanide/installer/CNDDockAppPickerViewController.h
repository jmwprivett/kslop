//
//  CNDDockAppPickerViewController.h
//  Cyanide
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^CNDDockAppPickerCompletion)(NSArray<NSString *> *orderedBundleIdentifiers);

/// Searchable, ordered application picker for filling additional dock slots.
///
/// Present this controller inside a UINavigationController. Tapping an app
/// appends it to the selection; tapping it again removes it. Consequently an
/// app can be moved to the end by deselecting and reselecting it.
@interface CNDDockAppPickerViewController : UITableViewController

/// The enforced maximum number of selected applications, clamped to 0...3.
@property (nonatomic, assign, readonly) NSUInteger selectionCapacity;

/// Current ordered selection. Saved identifiers that are no longer installed
/// remain here until the user removes them.
@property (nonatomic, copy, readonly) NSArray<NSString *> *selectedBundleIdentifiers;

/// Creates a picker. Duplicate and empty identifiers are discarded while the
/// first occurrence of each identifier preserves its input order. If legacy
/// input exceeds capacity it remains visible, but Done stays disabled until
/// enough entries are removed.
- (instancetype)initWithSelectedBundleIdentifiers:(NSArray<NSString *> *)selectedBundleIdentifiers
                                          capacity:(NSUInteger)capacity
                                        completion:(nullable CNDDockAppPickerCompletion)completion NS_DESIGNATED_INITIALIZER;

- (instancetype)initWithStyle:(UITableViewStyle)style NS_UNAVAILABLE;
- (instancetype)initWithCoder:(NSCoder *)coder NS_UNAVAILABLE;
- (instancetype)initWithNibName:(nullable NSString *)nibNameOrNil
                          bundle:(nullable NSBundle *)nibBundleOrNil NS_UNAVAILABLE;

@end

NS_ASSUME_NONNULL_END
