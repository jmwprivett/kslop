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
@property (nonatomic, assign) BOOL promptsForHideHomeBarRespring;
@property (nonatomic, assign) BOOL promptsForSystemEditRespring;
@property (nonatomic, copy, nullable) NSString *systemEditRespringTitle;
@property (nonatomic, copy, nullable) NSString *systemEditRespringMessage;
@end

NS_ASSUME_NONNULL_END
