// QDLicense.m - Kích hoạt key qua server, phản hồi được ký (ECDSA P-256).
// - URL server ghi cứng (đã mã hóa nhẹ), không đọc từ Info.plist nữa.
// - Chỉ chấp nhận phản hồi có chữ ký đúng + nonce khớp + giờ server lệch < 10 phút.
// Khi key hợp lệ gửi NSNotification "QDLicenseOK"; hết hạn/thu hồi gửi "QDLicenseExpired".

#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <sys/utsname.h>

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

// ---------- Dòng LED chạy vòng lặp + bảng thông tin (nhấn để mở/đóng) ----------
static const NSTimeInterval kBannerSeconds = 0;  // thời gian hiện (giây), 0 = hiện mãi
static const CGFloat kBannerSpeed = 70.0;        // tốc độ chữ chạy (điểm/giây)

// Thông tin key để hiện trong bảng
static NSString *gCurKey;
static long long gExpMs = 0;
static double gRemainSec = 0;
static CFTimeInterval gSyncMono = 0;

static UIWindow *gBWin;
static UIView *gRot, *gBar, *gClip, *gPanel;
static UILabel *gBLabel, *gPLabel;
static CADisplayLink *gBLink;
static NSString *gBText, *gBRepeat;
static CGFloat gBPeriod, gLastRot;
static NSUInteger gBUnitLen, gBN;
static CGSize gLastWS;
static CFTimeInterval gBStart;
static BOOL gPanelOn;

@interface QDPassWindow : UIWindow // chỉ nhận chạm trên thanh LED và bảng, còn lại xuyên xuống game
@end
@implementation QDPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    if (v && ((gBar && [v isDescendantOfView:gBar]) || (gPanel && !gPanel.hidden && [v isDescendantOfView:gPanel])))
        return v;
    return nil;
}
@end

static CGFloat QDNorm(CGFloat a) {
    while (a > M_PI) a -= 2 * M_PI;
    while (a <= -M_PI) a += 2 * M_PI;
    return a;
}

// Góc cần xoay để chữ luôn thẳng theo hướng cầm máy thực tế (game có thể tự xoay hình riêng)
static CGFloat QDRotation(UIWindowScene *sc) {
    CGFloat ad;
    switch (UIDevice.currentDevice.orientation) {
        case UIDeviceOrientationPortrait: ad = 0; break;
        case UIDeviceOrientationPortraitUpsideDown: ad = M_PI; break;
        case UIDeviceOrientationLandscapeLeft: ad = M_PI_2; break;
        case UIDeviceOrientationLandscapeRight: ad = -M_PI_2; break;
        default: return gLastRot; // nằm ngang/không rõ: giữ nguyên
    }
    CGFloat ai = 0;
    switch (sc.interfaceOrientation) {
        case UIInterfaceOrientationPortraitUpsideDown: ai = M_PI; break;
        case UIInterfaceOrientationLandscapeRight: ai = M_PI_2; break;
        case UIInterfaceOrientationLandscapeLeft: ai = -M_PI_2; break;
        default: ai = 0;
    }
    return QDNorm(ad - ai);
}

@interface QDBanner : NSObject
+ (void)showThanksTry:(int)attempt;
@end

@implementation QDBanner

+ (void)showThanksTry:(int)attempt {
    if (gBWin) return;
    UIWindowScene *scene = nil;
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
        if ([s isKindOfClass:UIWindowScene.class] &&
            s.activationState == UISceneActivationStateForegroundActive) { scene = (UIWindowScene *)s; break; }
    }
    if (!scene) {
        if (attempt < 5)
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self showThanksTry:attempt + 1]; });
        return;
    }
    [UIDevice.currentDevice beginGeneratingDeviceOrientationNotifications];

    gBWin = [[QDPassWindow alloc] initWithWindowScene:scene];
    gBWin.windowLevel = UIWindowLevelAlert + 100;
    gBWin.backgroundColor = UIColor.clearColor;
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = UIColor.clearColor;
    gBWin.rootViewController = vc;
    gBWin.hidden = NO;
    gBWin.alpha = 0;

    gRot = [UIView new];
    gRot.backgroundColor = UIColor.clearColor;
    [vc.view addSubview:gRot];

    gBar = [UIView new];
    gBar.backgroundColor = [UIColor colorWithWhite:0 alpha:0.78];
    gBar.layer.cornerRadius = 14;
    gBar.layer.borderWidth = 1.5;
    gBar.layer.shadowOpacity = 0.9;
    gBar.layer.shadowRadius = 6;
    gBar.layer.shadowOffset = CGSizeZero;
    [gBar addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(togglePanel)]];
    [gRot addSubview:gBar];

    gClip = [UIView new];
    gClip.clipsToBounds = YES;
    gClip.layer.cornerRadius = 14;
    gClip.userInteractionEnabled = NO;
    [gBar addSubview:gClip];

    gBText = @"★  Cảm ơn bạn đã sử dụng dịch vụ bên QDONENLITE  ★";
    gBLabel = [UILabel new];
    gBLabel.font = [UIFont boldSystemFontOfSize:15];
    gBLabel.lineBreakMode = NSLineBreakByClipping;
    [gClip addSubview:gBLabel];

    gPanel = [UIView new];
    gPanel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.88];
    gPanel.layer.cornerRadius = 14;
    gPanel.layer.borderWidth = 1.5;
    gPanel.hidden = YES;
    [gPanel addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(togglePanel)]];
    gPLabel = [UILabel new];
    gPLabel.numberOfLines = 0;
    gPLabel.textColor = UIColor.whiteColor;
    gPLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    [gPanel addSubview:gPLabel];
    [gRot addSubview:gPanel];

    gPanelOn = NO;
    gLastRot = 0;
    [self relayout];
    gBStart = CACurrentMediaTime();
    gBLink = [CADisplayLink displayLinkWithTarget:self selector:@selector(tick:)];
    gBLink.preferredFramesPerSecond = 30;
    [gBLink addToRunLoop:NSRunLoop.mainRunLoop forMode:NSRunLoopCommonModes];
}

// Đặt lại vị trí/hướng theo cách cầm máy, và dựng chuỗi chữ lặp liền mạch
+ (void)relayout {
    if (!gBWin) return;
    UIView *root = gBWin.rootViewController.view;
    CGSize ws = root.bounds.size;
    CGFloat rot = QDRotation(gBWin.windowScene);
    BOOL swap = fabs(fabs(rot) - M_PI_2) < 0.1;
    CGSize L = swap ? CGSizeMake(ws.height, ws.width) : ws;
    gLastRot = rot; gLastWS = ws;

    gRot.transform = CGAffineTransformIdentity;
    gRot.bounds = CGRectMake(0, 0, L.width, L.height);
    gRot.center = CGPointMake(ws.width / 2, ws.height / 2);
    gRot.transform = CGAffineTransformMakeRotation(rot);

    CGFloat bw = MAX(120, L.width - 80);
    gBar.frame = CGRectMake(40, 8, bw, 28);
    gClip.frame = gBar.bounds;

    NSString *unit = [gBText stringByAppendingString:@"        "];
    gBUnitLen = unit.length;
    NSDictionary *at = @{NSFontAttributeName: gBLabel.font};
    CGFloat uw = MAX(40, [unit sizeWithAttributes:at].width);
    gBN = (NSUInteger)ceil((bw + uw) / uw) + 1;
    NSMutableString *rep = [NSMutableString string];
    for (NSUInteger i = 0; i < gBN; i++) [rep appendString:unit];
    gBRepeat = rep;
    gBPeriod = [rep sizeWithAttributes:at].width / gBN;
    if (gPanelOn) [self layoutPanel];
}

+ (void)layoutPanel {
    CGSize L = gRot.bounds.size;
    CGFloat w = MIN(L.width - 80, 460);
    CGSize sz = [gPLabel sizeThatFits:CGSizeMake(w - 24, CGFLOAT_MAX)];
    gPanel.frame = CGRectMake((L.width - w) / 2, 44, w, sz.height + 24);
    gPLabel.frame = CGRectMake(12, 12, w - 24, sz.height);
}

+ (NSString *)dur:(double)sec {
    long long t = (long long)sec;
    long long d = t / 86400, h = (t % 86400) / 3600, m = (t % 3600) / 60, s = t % 60;
    NSMutableArray *p = [NSMutableArray array];
    if (d) [p addObject:[NSString stringWithFormat:@"%lld ngày", d]];
    if (d || h) [p addObject:[NSString stringWithFormat:@"%lld giờ", h]];
    if (d || h || m) [p addObject:[NSString stringWithFormat:@"%lld phút", m]];
    [p addObject:[NSString stringWithFormat:@"%lld giây", s]];
    return [p componentsJoinedByString:@" "];
}

+ (NSString *)infoText {
    NSString *exp, *remain;
    if (gExpMs > 0) {
        NSDateFormatter *f = [NSDateFormatter new];
        f.dateFormat = @"dd/MM/yyyy HH:mm:ss";
        exp = [f stringFromDate:[NSDate dateWithTimeIntervalSince1970:gExpMs / 1000.0]];
        double left = gRemainSec - (CACurrentMediaTime() - gSyncMono);
        remain = left <= 0 ? @"Đã hết hạn" : [self dur:left];
    } else {
        exp = @"Vĩnh viễn"; remain = @"Không giới hạn";
    }
    struct utsname u; uname(&u);
    UIDevice *d = UIDevice.currentDevice;
    return [NSString stringWithFormat:
        @"Key: %@\nHết hạn: %@\nCòn lại: %@\nUID máy: %@\nTên máy: %@ (%s)\nHệ điều hành: iOS %@\n— Nhấn lần nữa để đóng —",
        gCurKey ?: @"—", exp, remain, d.identifierForVendor.UUIDString ?: @"—",
        d.name, u.machine, d.systemVersion];
}

+ (void)togglePanel {
    gPanelOn = !gPanelOn;
    if (gPanelOn) {
        gPLabel.text = [self infoText];
        [self layoutPanel];
        gPanel.hidden = NO;
    } else {
        gPanel.hidden = YES;
    }
}

+ (void)tick:(CADisplayLink *)l {
    CFTimeInterval t = CACurrentMediaTime() - gBStart;
    if (kBannerSeconds > 0 && t > kBannerSeconds) { [self hide]; return; }
    gBWin.alpha = MIN(1.0, t / 0.4);

    // Phát hiện xoay máy hoặc đổi kích thước thì căn lại
    CGSize ws = gBWin.rootViewController.view.bounds.size;
    if (QDRotation(gBWin.windowScene) != gLastRot || !CGSizeEqualToSize(ws, gLastWS)) [self relayout];

    CGFloat phase = fmod(t * 0.35, 1.0);
    NSMutableAttributedString *as = [[NSMutableAttributedString alloc]
        initWithString:gBRepeat attributes:@{NSFontAttributeName: gBLabel.font}];
    for (NSUInteger i = 0; i < gBRepeat.length; i++) {
        CGFloat hue = fmod(phase + (CGFloat)(i % gBUnitLen) / gBUnitLen, 1.0);
        [as addAttribute:NSForegroundColorAttributeName
                   value:[UIColor colorWithHue:hue saturation:1 brightness:1 alpha:1]
                   range:NSMakeRange(i, 1)];
    }
    gBLabel.attributedText = as;

    UIColor *glow = [UIColor colorWithHue:phase saturation:1 brightness:1 alpha:1];
    gBar.layer.borderColor = glow.CGColor;
    gBar.layer.shadowColor = glow.CGColor;

    // Chạy từ phải sang trái, lặp liền mạch (các bản sao nối đuôi nhau)
    CGFloat x = -fmod(t * kBannerSpeed, gBPeriod);
    gBLabel.frame = CGRectMake(x, 0, gBPeriod * gBN + 4, gClip.bounds.size.height);

    if (gPanelOn) {
        gPanel.layer.borderColor = glow.CGColor;
        NSString *txt = [self infoText];
        if (![txt isEqualToString:gPLabel.text]) { gPLabel.text = txt; [self layoutPanel]; }
    }
}

+ (void)hide {
    [gBLink invalidate]; gBLink = nil;
    [UIDevice.currentDevice endGeneratingDeviceOrientationNotifications];
    [UIView animateWithDuration:0.4 animations:^{ gBWin.alpha = 0; } completion:^(BOOL f) {
        gBWin.hidden = YES; gBWin = nil; gRot = gBar = gClip = gPanel = nil; gBLabel = gPLabel = nil;
    }];
}

@end

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
                gCurKey = saved;
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
    gExpMs = exp;
    gRemainSec = exp > 0 ? (exp - st) / 1000.0 : 0;
    gSyncMono = CACurrentMediaTime();
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
    [QDBanner showThanksTry:0];
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
                        gCurKey = [key uppercaseString];
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
