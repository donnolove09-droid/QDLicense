// QDLicense.m - Kích hoạt key qua server (Render)
// Đọc SERVER_URL từ Info.plist của app. Khi key hợp lệ sẽ gửi
// NSNotification "QDLicenseOK" để tool bật tính năng.

#import <UIKit/UIKit.h>

static NSString *const kSavedKey = @"qd_license_key";
static NSString *const kLicenseOK = @"QDLicenseOK";

static void QDCall(NSString *path, NSString *key, void (^done)(BOOL ok, NSString *err)) {
    NSString *base = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"SERVER_URL"];
    NSURL *url = base.length ? [NSURL URLWithString:[base stringByAppendingString:path]] : nil;
    if (!url) { done(NO, @"missing_server_url"); return; }

    NSString *dev = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 60; // Render free có thể đang ngủ
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"key": key, @"device_id": dev}
                                                   options:0 error:nil];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
            BOOL ok = [j[@"ok"] boolValue];
            done(ok, ok ? nil : (j[@"error"] ?: @"network"));
        }] resume];
}

static UIViewController *QDTop(void) {
    UIWindow *w = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] &&
            s.activationState == UISceneActivationStateForegroundActive) {
            for (UIWindow *x in ((UIWindowScene *)s).windows)
                if (x.isKeyWindow) w = x;
        }
    }
    if (!w) w = UIApplication.sharedApplication.windows.firstObject;
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

@interface QDLicense : NSObject
@end

@implementation QDLicense

+ (void)load {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self start]; });
}

+ (void)start {
    NSString *saved = [[NSUserDefaults standardUserDefaults] stringForKey:kSavedKey];
    if (saved.length) {
        QDCall(@"/api/verify", saved, ^(BOOL ok, NSString *err) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) [self granted];
                else [self promptWithMessage:[self text:err]];
            });
        });
    } else {
        [self promptWithMessage:@"Nhập key để kích hoạt"];
    }
}

+ (void)granted {
    [[NSNotificationCenter defaultCenter] postNotificationName:kLicenseOK object:nil];
}

+ (NSString *)text:(NSString *)err {
    NSDictionary *m = @{
        @"invalid_key": @"Key không hợp lệ",
        @"device_mismatch": @"Key đã dùng trên thiết bị khác",
        @"expired": @"Key đã hết hạn",
        @"revoked": @"Key đã bị khóa",
        @"network": @"Không kết nối được server, thử lại sau",
    };
    return m[err] ?: @"Lỗi kích hoạt";
}

+ (void)promptWithMessage:(NSString *)msg {
    UIViewController *top = QDTop();
    if (!top) { // chưa có giao diện, thử lại
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self promptWithMessage:msg]; });
        return;
    }
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Kích hoạt"
                                                               message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"QDONENLITE-XXX-XXXX-XXX";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"Kích hoạt" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *x) {
            NSString *key = [a.textFields.firstObject.text
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            QDCall(@"/api/activate", key, ^(BOOL ok, NSString *err) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (ok) {
                        [[NSUserDefaults standardUserDefaults] setObject:key forKey:kSavedKey];
                        [self granted];
                    } else {
                        [self promptWithMessage:[self text:err]];
                    }
                });
            });
        }]];
    [top presentViewController:a animated:YES completion:nil];
}

@end
