//
//  InstallProgressViewController.h
//  Cyanide
//
//  Sileo-style install progress sheet: live log + spinner during apply, then
//  "Done" once settings_run_actions completes.
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface InstallProgressViewController : UIViewController
/// Queue review sets this before presentation so only PackageQueue's terminal
/// result can finish the activity UI. Direct Settings actions retain their
/// existing generic completion channel.
@property (nonatomic, assign) BOOL expectsPackageQueueCompletion;
@property (nonatomic, assign) BOOL promptsForHideHomeBarRespring;
@property (nonatomic, assign) BOOL promptsForSystemEditRespring;
@property (nonatomic, copy, nullable) NSString *systemEditRespringTitle;
@property (nonatomic, copy, nullable) NSString *systemEditRespringMessage;
/// Re-enters the existing exact 3-2-1 flow for an already durable
/// AwaitingRespring transaction. Does not commit or mutate queue state.
- (void)beginSavedQueueRespringCountdown;
@end

NS_ASSUME_NONNULL_END
