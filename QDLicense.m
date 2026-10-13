// QDLicense.m - Kích hoạt key qua server, phản hồi được ký (ECDSA P-256).
// - URL server ghi cứng (đã mã hóa nhẹ), không đọc từ Info.plist nữa.
// - Chỉ chấp nhận phản hồi có chữ ký đúng + nonce khớp + giờ server lệch < 10 phút.
// Khi key hợp lệ gửi NSNotification "QDLicenseOK"; hết hạn/thu hồi gửi "QDLicenseExpired".

#import <UIKit/UIKit.h>
#import <Security/Security.h>

static NSString *const kSavedKey = @"qd_license_key";
static NSString *const kLicenseOK = @"QDLicenseOK";
static NSString *const kLicenseExpired = @"QDLicenseExpired";
static BOOL gPrompting = NO;
static BOOL gGranted = NO;
static NSUInteger gGen = 0;
// YES: hết hạn/bị thu hồi thì thoát game, mở lại phải nhập key mới. NO: chỉ hiện ô nhập key mới.
static const BOOL kKickOnExpire = YES;
typedef void (^QDDone)(BOOL ok, NSString *err, long long exp, long long st);

// Khóa công khai (65 byte, X9.63) khớp với SIGN_PRIVATE_KEY trên server
static NSString *const kPubB64 = @"BEai/5Z180QPNEb+K5AgFOJHcuUD+j+bJeuXsMTYFpe2ECMAjMMKTKN6BQYRRgGQpENo/l36Bv+ohF0KIbcLEyE=";

// URL server mã hóa XOR
static const unsigned char kEnc[] = { 0x32, 0xB7, 0x63, 0xFE, 0x5E, 0x4B, 0x75, 0xEC, 0x66, 0xEA, 0x42, 0x1F, 0x32, 0xAA, 0x7F, 0xE7, 0x03, 0x1E, 0x34, 0xB1, 0x72, 0xE0, 0x49, 0x14, 0x28, 0xED, 0x74, 0xE1, 0x40 };
static const unsigned char kXor[] = { 0x5A, 0xC3, 0x17, 0x8E, 0x2D, 0x71 };

static NSString *QDBase(void) {
    char buf[sizeof(kEnc) + 1];
    for (size_t i = 0; i < sizeof(kEnc); i++) buf[i] = kEnc[i] ^ kXor[i % sizeof(kXor)];
    buf[sizeof(kEnc)] = 0;
    return [NSString stringWithUTF8String:buf];
}

static BOOL QDFatal(NSString *err) {
    return [@[@"invalid_key", @"device_mismatch", @"expired", @"revoked"] containsObject:err ?: @""];
}

static SecKeyRef QDPubKey(void) {
    static SecKeyRef k = NULL;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSData *raw = [[NSData alloc] initWithBase64EncodedString:kPubB64 options:0];
        NSDictionary *a = @{ (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                             (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic };
        if (raw) k = SecKeyCreateWithData((__bridge CFDataRef)raw, (__bridge CFDictionaryRef)a, NULL);
    });
    return k;
}

static BOOL QDVerify(NSString *msg, NSString *sigB64) {
    SecKeyRef k = QDPubKey();
    NSData *sig = sigB64.length ? [[NSData alloc] initWithBase64EncodedString:sigB64 options:0] : nil;
    if (!k || !sig) return NO;
    return SecKeyVerifySignature(k, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        (__bridge CFDataRef)[msg dataUsingEncoding:NSUTF8StringEncoding], (__bridge CFDataRef)sig, NULL);
}

static void QDCall(NSString *path, NSString *key, QDDone done) {
    key = [[key stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
    NSURL *url = [NSURL URLWithString:[QDBase() stringByAppendingString:path]];
    NSString *dev = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSString *nonce = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 60; // Render free có thể đang ngủ
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = [NSJSONSerialization dataWithJSONObject:@{@"key": key, @"device_id": dev, @"nonce": nonce}
                                                   options:0 error:nil];

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
            NSDictionary *j = d ? [NSJSONSerialization JSONObjectWithData:d options:0 error:nil] : nil;
            if (![j isKindOfClass:NSDictionary.class]) { done(NO, @"network", 0, 0); return; }

            BOOL ok = [j[@"ok"] boolValue];
            NSString *err = [j[@"error"] isKindOfClass:NSString.class] ? j[@"error"] : @"";
            long long exp = [j[@"expires_at"] isKindOfClass:NSNumber.class] ? [j[@"expires_at"] longLongValue] : 0;
            long long st = [j[@"server_time"] longLongValue];
            NSString *msg = [NSString stringWithFormat:@"%d|%@|%lld|%lld|%@|%@|%@",
                             ok ? 1 : 0, err, exp, st, nonce, key, dev];

            if (![j[@"nonce"] isEqual:nonce] || !QDVerify(msg, j[@"sig"])) { done(NO, @"bad_response", 0, 0); return; }
            long long now = (long long)([[NSDate date] timeIntervalSince1970] * 1000);
            if (llabs(now - st) > 600000) { done(NO, @"bad_time", 0, 0); return; }
            done(ok, ok ? nil : (err.length ? err : @"error"), exp, st);
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
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(recheck)
        name:UIApplicationDidBecomeActiveNotification object:nil];
    [NSTimer scheduledTimerWithTimeInterval:30 target:self selector:@selector(recheck)
        userInfo:nil repeats:YES];
    [self recheck];
}

+ (void)recheck {
    if (gPrompting) return;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *saved = [ud stringForKey:kSavedKey];
    if (!saved.length) { [self promptWithMessage:@"Nhập key để kích hoạt"]; return; }
    QDCall(@"/api/verify", saved, ^(BOOL ok, NSString *err, long long exp, long long st) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                [self scheduleExpiry:exp serverTime:st];
                if (!gGranted) { gGranted = YES; [self granted]; }
                return;
            }
            if (QDFatal(err)) { [self kick:err]; return; }
            if (!gGranted) [self promptWithMessage:[self text:err]]; // lỗi mạng lúc mới mở
            // lỗi mạng khi đang chạy: không cấp quyền mới, lần sau thử lại
        });
    });
}

// Hẹn đúng lúc hết hạn (tính theo giờ server, không phụ thuộc đồng hồ máy)
+ (void)scheduleExpiry:(long long)exp serverTime:(long long)st {
    gGen++;
    if (exp <= 0) return; // key vĩnh viễn
    NSUInteger g = gGen;
    double secs = MAX(0, (exp - st) / 1000.0) + 1.0;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(secs * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ if (g == gGen) [self recheck]; });
}

// Key hết hạn / bị thu hồi / sai máy: xóa key đã lưu, thoát game (hoặc hiện ô nhập key mới)
+ (void)kick:(NSString *)err {
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kSavedKey];
    gGranted = NO; gGen++;
    [[NSNotificationCenter defaultCenter] postNotificationName:kLicenseExpired
        object:nil userInfo:@{@"error": err ?: @""}];
    if (!kKickOnExpire) { [self promptWithMessage:[self text:err]]; return; }
    gPrompting = YES; // chặn các lần kiểm tra khác trong lúc chờ thoát
    UIViewController *top = QDTop();
    if (top) {
        NSString *msg = [[self text:err] stringByAppendingString:@"\nGame sẽ thoát. Hãy mở lại và nhập key mới."];
        UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Thông báo"
            message:msg preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"Thoát" style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *x) { exit(0); }]];
        [top presentViewController:a animated:YES completion:nil];
    }
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(6 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ exit(0); });
}

+ (void)granted {
    [[NSNotificationCenter defaultCenter] postNotificationName:kLicenseOK object:nil];
}

+ (NSString *)text:(NSString *)err {
    NSDictionary *m = @{
        @"invalid_key": @"Key không hợp lệ",
        @"device_mismatch": @"Key đã dùng trên thiết bị khác",
        @"expired": @"Key đã hết hạn, vui lòng nhập key mới",
        @"revoked": @"Key đã bị khóa",
        @"network": @"Không kết nối được server, thử lại sau",
        @"bad_response": @"Phản hồi từ server không hợp lệ",
        @"bad_time": @"Giờ trên máy không đúng, hãy bật cập nhật giờ tự động",
    };
    return m[err] ?: @"Lỗi kích hoạt";
}

+ (void)promptWithMessage:(NSString *)msg {
    UIViewController *top = QDTop();
    if (!top) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self promptWithMessage:msg]; });
        return;
    }
    gPrompting = YES;
    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"Kích hoạt"
                                                               message:msg
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"QDONENLITE-XXX-XXXX-XXX";
        tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    }];
    [a addAction:[UIAlertAction actionWithTitle:@"Kích hoạt" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *x) {
            gPrompting = NO;
            NSString *key = [a.textFields.firstObject.text
                stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
            QDCall(@"/api/activate", key, ^(BOOL ok, NSString *err, long long exp, long long st) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (ok) {
                        [[NSUserDefaults standardUserDefaults] setObject:key forKey:kSavedKey];
                        gGranted = YES;
                        [self scheduleExpiry:exp serverTime:st];
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
