// QDLicense.m - Kích hoạt key, phản hồi được ký (ECDSA P-256).
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

static const unsigned char kA[] = { 0x1C, 0xAA, 0xE4, 0xAC, 0x9E, 0xF2, 0x57, 0x5B, 0xAF, 0xF4, 0xB3, 0x83, 0xAD, 0x16, 0x18, 0xB7, 0xE4, 0xB9, 0x9E, 0xAD, 0x0E, 0x11, 0xAC, 0xFB, 0xB9, 0x94, 0xE6, 0x17, 0x1A, 0xAC, 0xF5, 0xB2, 0x89, 0xAD, 0x0A, 0x5A, 0xBD, 0xFF, 0xB1 };
static const unsigned char kB[] = { 0x74, 0xDE, 0x90, 0xDC, 0xED, 0xC8, 0x78 };
static NSString *QDBase(void) {
    char buf[sizeof(kA) + 1];
    for (size_t i = 0; i < sizeof(kA); i++) buf[i] = kA[i] ^ kB[i % sizeof(kB)];
    buf[sizeof(kA)] = 0;
    return [NSString stringWithUTF8String:buf];
}

// Avatar (JPEG nhúng sẵn)
static NSString *const kAvB64 = @"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";
static UIImage *QDAvatar(void) {
    static UIImage *img;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSData *d = [[NSData alloc] initWithBase64EncodedString:kAvB64 options:0];
        if (d) img = [UIImage imageWithData:d scale:3];
    });
    return img;
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

// Chuẩn hóa key: viết hoa, bỏ khoảng trắng, đổi mọi loại dấu gạch ngang lạ thành "-"
static NSString *QDNormKey(NSString *k) {
    NSMutableString *m = [[(k ?: @"") uppercaseString] mutableCopy];
    for (NSString *d in @[@"\u2010", @"\u2011", @"\u2012", @"\u2013", @"\u2014", @"\u2015", @"\u2212"])
        [m replaceOccurrencesOfString:d withString:@"-" options:0 range:NSMakeRange(0, m.length)];
    return [[m componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet]
            componentsJoinedByString:@""];
}

static void QDCall(NSString *path, NSString *key, QDDone done) {
    key = QDNormKey(key);
    NSURL *url = [NSURL URLWithString:[QDBase() stringByAppendingString:path]];
    NSString *dev = [[[UIDevice currentDevice] identifierForVendor] UUIDString] ?: @"unknown";
    NSString *nonce = [[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""];

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 60;
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

            if (![j[@"nonce"] isEqual:nonce]) { done(NO, @"bad_nonce", 0, 0); return; }
            if (!QDVerify(msg, j[@"sig"])) { done(NO, @"bad_sig", 0, 0); return; }
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

// ---------- Dòng LED chạy vòng lặp + bảng thông tin (nhấn để mở/đóng, nhấn 3 lần để thu nhỏ thành avatar tròn) ----------
static const NSTimeInterval kBannerSeconds = 0;  // thời gian hiện (giây), 0 = hiện mãi
static const CGFloat kBannerSpeed = 70.0;        // tốc độ chữ chạy (điểm/giây)
// Thanh LED luôn nằm chính giữa màn hình, độ rộng theo tỉ lệ chiều ngang
static const CGFloat kBarWidthFrac = 0.54;       // độ rộng thanh: 54% màn hình (tăng = dài hơn)
static const CGFloat kBubbleSize = 46;           // đường kính hình tròn avatar khi thu nhỏ

// Thông tin key để hiện trong bảng
static NSString *const kHideRecKey = @"qd_hide_on_record";
static NSString *gCurKey;
static long long gExpMs = 0;
static double gRemainSec = 0;
static CFTimeInterval gSyncMono = 0;

static UIWindow *gBWin;
static UIView *gRot, *gBar, *gClip, *gPanel, *gBubble, *gSwRow;
static UILabel *gBLabel, *gPLabel, *gSwLabel, *gHint;
static UISwitch *gSwitch;
static NSTimer *gBTimer;
static NSString *gBText, *gBRepeat;
static CGFloat gBPeriod, gLastRot;
static NSUInteger gBUnitLen, gBN;
static CGSize gLastWS;
static CFTimeInterval gBStart;
static BOOL gPanelOn, gCollapsed, gBubbleSet;
static CGPoint gBubblePos;

// Mặc định BẬT: ẩn LED khi đang quay màn hình / phản chiếu màn hình
static BOOL QDHideOnRec(void) {
    id v = [[NSUserDefaults standardUserDefaults] objectForKey:kHideRecKey];
    return v ? [v boolValue] : YES;
}

@interface QDPassWindow : UIWindow // chỉ nhận chạm trên thanh LED và bảng, còn lại xuyên xuống game
@end
@implementation QDPassWindow
- (UIView *)hitTest:(CGPoint)p withEvent:(UIEvent *)e {
    UIView *v = [super hitTest:p withEvent:e];
    if (v && ((gBar && [v isDescendantOfView:gBar]) ||
              (gPanel && !gPanel.hidden && [v isDescendantOfView:gPanel]) ||
              (gBubble && !gBubble.hidden && [v isDescendantOfView:gBubble])))
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

// Viền/bóng đổi màu cầu vồng bằng animation của hệ thống (không tốn CPU)
static void QDGlowAnim(CALayer *l) {
    static NSArray *cols;
    static dispatch_once_t t;
    dispatch_once(&t, ^{
        NSMutableArray *a = [NSMutableArray array];
        for (int i = 0; i <= 8; i++)
            [a addObject:(id)[UIColor colorWithHue:i / 8.0 saturation:1 brightness:1 alpha:1].CGColor];
        cols = a;
    });
    for (NSString *kp in @[@"borderColor", @"shadowColor"]) {
        CAKeyframeAnimation *a = [CAKeyframeAnimation animationWithKeyPath:kp];
        a.values = cols;
        a.duration = 3.0;
        a.repeatCount = HUGE_VALF;
        a.removedOnCompletion = NO;
        [l addAnimation:a forKey:[@"glow_" stringByAppendingString:kp]];
    }
}

@interface QDBanner : NSObject
+ (void)showThanksTry:(int)attempt;
+ (void)collapse;
+ (void)expand;
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
    UITapGestureRecognizer *one = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(togglePanel)];
    UITapGestureRecognizer *three = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(collapse)];
    three.numberOfTapsRequired = 3;
    [one requireGestureRecognizerToFail:three];
    [gBar addGestureRecognizer:one];
    [gBar addGestureRecognizer:three];
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

    // Bảng thông tin + công tắc ẩn khi quay màn hình
    gPanel = [UIView new];
    gPanel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.88];
    gPanel.layer.cornerRadius = 14;
    gPanel.layer.borderWidth = 1.5;
    gPanel.layer.shadowOpacity = 0.6;
    gPanel.layer.shadowRadius = 6;
    gPanel.layer.shadowOffset = CGSizeZero;
    gPanel.hidden = YES;
    [gPanel addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(togglePanel)]];
    gPLabel = [UILabel new];
    gPLabel.numberOfLines = 0;
    gPLabel.textColor = UIColor.whiteColor;
    gPLabel.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightMedium];
    [gPanel addSubview:gPLabel];

    gSwRow = [UIView new];
    gSwLabel = [UILabel new];
    gSwLabel.text = @"Ẩn LED khi quay màn hình";
    gSwLabel.textColor = UIColor.whiteColor;
    gSwLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [gSwRow addSubview:gSwLabel];
    gSwitch = [UISwitch new];
    gSwitch.on = QDHideOnRec();
    gSwitch.onTintColor = [UIColor colorWithRed:0.18 green:0.62 blue:1 alpha:1];
    [gSwitch addTarget:self action:@selector(hideSwitchChanged:) forControlEvents:UIControlEventValueChanged];
    [gSwRow addSubview:gSwitch];
    [gPanel addSubview:gSwRow];

    gHint = [UILabel new];
    gHint.numberOfLines = 0;
    gHint.text = @"Nhấn vào bảng để đóng • Nhấn 3 lần vào thanh LED để thu nhỏ";
    gHint.textColor = [UIColor colorWithWhite:1 alpha:0.5];
    gHint.font = [UIFont systemFontOfSize:10.5];
    [gPanel addSubview:gHint];
    [gRot addSubview:gPanel];

    // Hình tròn avatar (hiện khi thu nhỏ thanh LED)
    gBubble = [UIView new];
    gBubble.bounds = CGRectMake(0, 0, kBubbleSize, kBubbleSize);
    gBubble.backgroundColor = [UIColor colorWithRed:0.02 green:0.04 blue:0.12 alpha:1];
    gBubble.layer.cornerRadius = kBubbleSize / 2;
    gBubble.layer.borderWidth = 2.5;
    gBubble.layer.shadowOpacity = 0.9;
    gBubble.layer.shadowRadius = 6;
    gBubble.layer.shadowOffset = CGSizeZero;
    gBubble.layer.shadowPath = [UIBezierPath bezierPathWithOvalInRect:gBubble.bounds].CGPath;
    UIImageView *av = [[UIImageView alloc] initWithImage:QDAvatar()];
    av.frame = CGRectInset(gBubble.bounds, 3, 3);
    av.contentMode = UIViewContentModeScaleAspectFill;
    av.clipsToBounds = YES;
    av.layer.cornerRadius = av.bounds.size.width / 2;
    av.userInteractionEnabled = NO;
    [gBubble addSubview:av];
    [gBubble addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(expand)]];
    [gBubble addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(bubblePan:)]];
    gBubble.hidden = YES;
    gBubble.alpha = 0;
    [gRot addSubview:gBubble];

    gCollapsed = NO; gBubbleSet = NO;
    gPanelOn = NO;
    gLastRot = 0;

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(applyRecordingState)
            name:UIScreenCapturedDidChangeNotification object:nil];
    });

    [self relayout];
    [self ensureAnims];
    [self applyRecordingState];
    gBStart = CACurrentMediaTime();
    [UIView animateWithDuration:0.4 animations:^{ gBWin.alpha = 1; }];

    // Chỉ kiểm tra nhẹ vài lần mỗi giây; hiệu ứng chạy do hệ thống đảm nhiệm
    gBTimer = [NSTimer timerWithTimeInterval:0.4 target:self selector:@selector(tick:) userInfo:nil repeats:YES];
    gBTimer.tolerance = 0.15;
    [[NSRunLoop mainRunLoop] addTimer:gBTimer forMode:NSRunLoopCommonModes];
}

// Đang quay/phản chiếu màn hình và công tắc bật => ẩn toàn bộ LED + thanh trên cùng
+ (void)applyRecordingState {
    if (!gBWin) return;
    UIScreen *scr = gBWin.windowScene.screen ?: UIScreen.mainScreen;
    BOOL hide = QDHideOnRec() && scr.isCaptured;
    if (gBWin.hidden != hide) gBWin.hidden = hide;
}

+ (void)hideSwitchChanged:(UISwitch *)sw {
    [[NSUserDefaults standardUserDefaults] setBool:sw.on forKey:kHideRecKey];
    [self applyRecordingState];
}

+ (void)ensureAnims {
    if (!gBar) return;
    for (UIView *v in @[gBar, gBubble, gPanel])
        if (![v.layer animationForKey:@"glow_borderColor"]) QDGlowAnim(v.layer);
    if (gBLabel && ![gBLabel.layer animationForKey:@"scroll"]) [self startScroll];
}

// Chữ chạy bằng animation của hệ thống, lặp liền mạch
+ (void)startScroll {
    [gBLabel.layer removeAnimationForKey:@"scroll"];
    if (gBPeriod <= 0) return;
    CABasicAnimation *a = [CABasicAnimation animationWithKeyPath:@"transform.translation.x"];
    a.fromValue = @0;
    a.toValue = @(-gBPeriod);
    a.duration = gBPeriod / kBannerSpeed;
    a.repeatCount = HUGE_VALF;
    a.timingFunction = [CAMediaTimingFunction functionWithName:kCAMediaTimingFunctionLinear];
    a.removedOnCompletion = NO;
    [gBLabel.layer addAnimation:a forKey:@"scroll"];
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

    CGFloat bw = MAX(160, L.width * kBarWidthFrac);
    gBar.frame = CGRectMake((L.width - bw) / 2, 8, bw, 28); // căn giữa hai bên cân bằng
    gBar.layer.shadowPath = [UIBezierPath bezierPathWithRoundedRect:gBar.bounds cornerRadius:14].CGPath;
    gClip.frame = gBar.bounds;
    if (gBubbleSet) [self placeBubble];

    NSString *unit = [gBText stringByAppendingString:@"        "];
    gBUnitLen = unit.length;
    NSDictionary *at = @{NSFontAttributeName: gBLabel.font};
    CGFloat uw = MAX(40, [unit sizeWithAttributes:at].width);
    gBN = (NSUInteger)ceil((bw + uw) / uw) + 1;
    NSMutableString *rep = [NSMutableString string];
    for (NSUInteger i = 0; i < gBN; i++) [rep appendString:unit];
    gBRepeat = rep;
    gBPeriod = [rep sizeWithAttributes:at].width / gBN;

    // Tô màu cầu vồng một lần duy nhất (không cập nhật từng khung hình)
    NSMutableAttributedString *as = [[NSMutableAttributedString alloc] initWithString:gBRepeat attributes:at];
    for (NSUInteger i = 0; i < gBRepeat.length; i++) {
        CGFloat hue = (CGFloat)(i % gBUnitLen) / gBUnitLen;
        [as addAttribute:NSForegroundColorAttributeName
                   value:[UIColor colorWithHue:hue saturation:1 brightness:1 alpha:1]
                   range:NSMakeRange(i, 1)];
    }
    gBLabel.attributedText = as;
    gBLabel.frame = CGRectMake(0, 0, gBPeriod * gBN + 4, gClip.bounds.size.height);
    [self startScroll];
    if (gPanelOn) [self layoutPanel];
}

+ (void)layoutPanel {
    CGSize L = gRot.bounds.size;
    CGFloat w = MIN(MAX(gBar.frame.size.width, 360), L.width - 20);
    CGFloat x = gBar.frame.origin.x + (gBar.frame.size.width - w) / 2; // căn giữa dưới thanh LED
    x = MAX(10, MIN(x, L.width - w - 10));
    CGFloat iw = w - 24;
    CGSize sz = [gPLabel sizeThatFits:CGSizeMake(iw, CGFLOAT_MAX)];
    CGFloat y = 12;
    gPLabel.frame = CGRectMake(12, y, iw, sz.height); y += sz.height + 8;
    gSwRow.frame = CGRectMake(12, y, iw, 34); y += 34 + 2;
    gSwLabel.frame = CGRectMake(0, 0, iw - 60, 34);
    gSwitch.frame = CGRectMake(iw - gSwitch.bounds.size.width, (34 - gSwitch.bounds.size.height) / 2,
                               gSwitch.bounds.size.width, gSwitch.bounds.size.height);
    CGSize hs = [gHint sizeThatFits:CGSizeMake(iw, CGFLOAT_MAX)];
    gHint.frame = CGRectMake(12, y, iw, hs.height); y += hs.height + 12;
    gPanel.frame = CGRectMake(x, 44, w, y);
    gPanel.layer.shadowPath = [UIBezierPath bezierPathWithRoundedRect:gPanel.bounds cornerRadius:14].CGPath;
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
        @"Key: %@\nHết hạn: %@\nCòn lại: %@\nUID máy: %@\nTên máy: %@ (%s)\nHệ điều hành: iOS %@",
        gCurKey ?: @"—", exp, remain, d.identifierForVendor.UUIDString ?: @"—",
        d.name, u.machine, d.systemVersion];
}

+ (void)placeBubble {
    CGSize L = gRot.bounds.size;
    CGFloat r = kBubbleSize / 2 + 4;
    gBubblePos.x = MAX(r, MIN(L.width - r, gBubblePos.x));
    gBubblePos.y = MAX(r, MIN(L.height - r, gBubblePos.y));
    gBubble.center = gBubblePos;
}

// Nhấn 3 lần vào thanh LED: thu nhỏ thành hình tròn avatar
+ (void)collapse {
    if (gCollapsed || !gBar) return;
    gCollapsed = YES;
    gPanelOn = NO; gPanel.hidden = YES;
    if (!gBubbleSet) {
        gBubblePos = CGPointMake(CGRectGetMidX(gBar.frame), CGRectGetMidY(gBar.frame));
        gBubbleSet = YES;
    }
    [self placeBubble];
    gBubble.hidden = NO;
    gBubble.alpha = 0;
    gBubble.transform = CGAffineTransformMakeScale(0.3, 0.3);
    [UIView animateWithDuration:0.4 delay:0 usingSpringWithDamping:0.72 initialSpringVelocity:0.8 options:0
        animations:^{
            gBar.transform = CGAffineTransformMakeScale(0.12, 0.6);
            gBar.alpha = 0;
            gBubble.alpha = 1;
            gBubble.transform = CGAffineTransformIdentity;
        } completion:^(BOOL f) {
            if (gCollapsed) { gBar.hidden = YES; gBar.transform = CGAffineTransformIdentity; }
        }];
}

// Chạm vào hình tròn: mở lại thanh LED
+ (void)expand {
    if (!gCollapsed) return;
    gCollapsed = NO;
    gBar.hidden = NO;
    gBar.alpha = 0;
    gBar.transform = CGAffineTransformMakeScale(0.12, 0.6);
    [UIView animateWithDuration:0.4 delay:0 usingSpringWithDamping:0.8 initialSpringVelocity:0.6 options:0
        animations:^{
            gBar.alpha = 1;
            gBar.transform = CGAffineTransformIdentity;
            gBubble.alpha = 0;
            gBubble.transform = CGAffineTransformMakeScale(0.3, 0.3);
        } completion:^(BOOL f) {
            if (!gCollapsed) { gBubble.hidden = YES; gBubble.transform = CGAffineTransformIdentity; }
        }];
}

// Kéo hình tròn đi nơi khác
+ (void)bubblePan:(UIPanGestureRecognizer *)g {
    static CGPoint start;
    if (g.state == UIGestureRecognizerStateBegan) start = gBubblePos;
    CGPoint t = [g translationInView:gRot];
    gBubblePos = CGPointMake(start.x + t.x, start.y + t.y);
    [self placeBubble];
}

+ (void)togglePanel {
    gPanelOn = !gPanelOn;
    if (gPanelOn) {
        gPLabel.text = [self infoText];
        gSwitch.on = QDHideOnRec();
        [self layoutPanel];
        gPanel.hidden = NO;
    } else {
        gPanel.hidden = YES;
    }
}

+ (void)tick:(NSTimer *)tm {
    if (!gBWin) return;
    if (kBannerSeconds > 0 && CACurrentMediaTime() - gBStart > kBannerSeconds) { [self hide]; return; }
    [self applyRecordingState];
    if (gBWin.hidden) return; // đang ẩn vì quay màn hình
    if (gBWin.windowLevel < UIWindowLevelAlert + 100) gBWin.windowLevel = UIWindowLevelAlert + 100;

    // Phát hiện xoay máy hoặc đổi kích thước thì căn lại
    CGSize ws = gBWin.rootViewController.view.bounds.size;
    if (QDRotation(gBWin.windowScene) != gLastRot || !CGSizeEqualToSize(ws, gLastWS)) [self relayout];

    [self ensureAnims]; // hệ thống xóa animation khi app ra nền: gắn lại

    if (gPanelOn) {
        NSString *txt = [self infoText];
        if (![txt isEqualToString:gPLabel.text]) { gPLabel.text = txt; [self layoutPanel]; }
    }
}

+ (void)hide {
    [gBTimer invalidate]; gBTimer = nil;
    [UIDevice.currentDevice endGeneratingDeviceOrientationNotifications];
    [UIView animateWithDuration:0.4 animations:^{ gBWin.alpha = 0; } completion:^(BOOL f) {
        gBWin.hidden = YES; gBWin = nil;
        gRot = gBar = gClip = gPanel = gBubble = gSwRow = nil;
        gBLabel = gPLabel = gSwLabel = gHint = nil; gSwitch = nil;
        gCollapsed = NO; gBubbleSet = NO;
    }];
}

@end

// ---------- Màn hình nhập key ----------
static NSString *const kPromptHint = @"Nhập key để kích hoạt";
typedef void (^QDKeySubmit)(NSString *key);

@interface QDKeyVC : UIViewController <UITextFieldDelegate>
@property (nonatomic, copy) QDKeySubmit onSubmit;
- (void)showMessage:(NSString *)m error:(BOOL)err;
- (void)setBusy:(BOOL)b;
@end

@implementation QDKeyVC {
    UIView *_dim, *_card, *_logoWrap, *_pill, *_divider;
    UIImageView *_logo, *_pillIcon;
    UILabel *_title, *_tag, *_msg, *_foot;
    UITextField *_tf;
    UIButton *_btn;
    UIActivityIndicatorView *_spin;
    CAGradientLayer *_cardGrad, *_btnGrad;
    CGFloat _kb;
    BOOL _busy, _err;
}

+ (UIColor *)blue { return [UIColor colorWithRed:0.18 green:0.62 blue:1.0 alpha:1]; }
+ (UIColor *)red { return [UIColor colorWithRed:1 green:0.45 blue:0.48 alpha:1]; }

- (UIInterfaceOrientationMask)supportedInterfaceOrientations { return UIInterfaceOrientationMaskAll; }
- (BOOL)shouldAutorotate { return YES; }

- (NSAttributedString *)btnTitle {
    return [[NSAttributedString alloc] initWithString:@"KÍCH HOẠT"
        attributes:@{NSFontAttributeName: [UIFont systemFontOfSize:15 weight:UIFontWeightHeavy],
                     NSKernAttributeName: @1.8, NSForegroundColorAttributeName: UIColor.whiteColor}];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    UIColor *blue = [QDKeyVC blue];
    self.view.backgroundColor = UIColor.clearColor;

    // Nền tối đơn giản (không làm mờ để không nặng máy khi game đang chạy phía sau)
    _dim = [[UIView alloc] initWithFrame:self.view.bounds];
    _dim.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    _dim.backgroundColor = [UIColor colorWithRed:0.01 green:0.02 blue:0.07 alpha:0.9];
    [self.view addSubview:_dim];
    UITapGestureRecognizer *bgTap = [[UITapGestureRecognizer alloc] initWithTarget:self.view action:@selector(endEditing:)];
    bgTap.cancelsTouchesInView = NO;
    [self.view addGestureRecognizer:bgTap];

    // Thẻ chính
    _card = [UIView new];
    _card.layer.cornerRadius = 26;
    _card.layer.borderWidth = 1.2;
    _card.layer.borderColor = [blue colorWithAlphaComponent:0.8].CGColor;
    _card.layer.shadowColor = blue.CGColor;
    _card.layer.shadowRadius = 24;
    _card.layer.shadowOpacity = 0.5;
    _card.layer.shadowOffset = CGSizeZero;
    _cardGrad = [CAGradientLayer layer];
    _cardGrad.colors = @[(id)[UIColor colorWithRed:0.06 green:0.13 blue:0.30 alpha:1].CGColor,
                         (id)[UIColor colorWithRed:0.02 green:0.04 blue:0.12 alpha:1].CGColor];
    _cardGrad.startPoint = CGPointMake(0, 0);
    _cardGrad.endPoint = CGPointMake(0.8, 1);
    _cardGrad.cornerRadius = 26;
    [_card.layer addSublayer:_cardGrad];
    [self.view addSubview:_card];

    _divider = [UIView new];
    _divider.backgroundColor = [blue colorWithAlphaComponent:0.25];
    [_card addSubview:_divider];

    // Avatar tròn
    _logoWrap = [UIView new];
    _logoWrap.layer.cornerRadius = 44;
    _logoWrap.layer.borderWidth = 2.5;
    _logoWrap.layer.borderColor = blue.CGColor;
    _logoWrap.layer.shadowColor = blue.CGColor;
    _logoWrap.layer.shadowRadius = 12;
    _logoWrap.layer.shadowOpacity = 0.9;
    _logoWrap.layer.shadowOffset = CGSizeZero;
    _logoWrap.backgroundColor = [UIColor colorWithRed:0.02 green:0.04 blue:0.12 alpha:1];
    _logo = [[UIImageView alloc] initWithImage:QDAvatar()];
    _logo.contentMode = UIViewContentModeScaleAspectFill;
    _logo.clipsToBounds = YES;
    [_logoWrap addSubview:_logo];
    [_card addSubview:_logoWrap];

    // Tiêu đề
    UIFont *tf = [UIFont systemFontOfSize:26 weight:UIFontWeightHeavy];
    UIFontDescriptor *fd = [tf.fontDescriptor fontDescriptorWithSymbolicTraits:UIFontDescriptorTraitItalic];
    if (fd) tf = [UIFont fontWithDescriptor:fd size:26];
    NSMutableAttributedString *ts = [[NSMutableAttributedString alloc] initWithString:@"QDON ENLITE"
        attributes:@{NSFontAttributeName: tf, NSKernAttributeName: @1.5, NSForegroundColorAttributeName: UIColor.whiteColor}];
    [ts addAttribute:NSForegroundColorAttributeName value:blue range:NSMakeRange(5, 6)];
    _title = [UILabel new];
    _title.attributedText = ts;
    _title.textAlignment = NSTextAlignmentCenter;
    _title.adjustsFontSizeToFitWidth = YES;
    _title.minimumScaleFactor = 0.6;
    [_card addSubview:_title];

    _tag = [UILabel new];
    _tag.attributedText = [[NSAttributedString alloc] initWithString:@"PLAY SMARTER – WIN EASIER"
        attributes:@{NSFontAttributeName: [UIFont systemFontOfSize:10 weight:UIFontWeightMedium],
                     NSKernAttributeName: @2.0,
                     NSForegroundColorAttributeName: [UIColor colorWithRed:0.62 green:0.78 blue:1 alpha:0.8]}];
    _tag.textAlignment = NSTextAlignmentCenter;
    _tag.adjustsFontSizeToFitWidth = YES;
    _tag.minimumScaleFactor = 0.6;
    [_card addSubview:_tag];

    // Dải thông báo (xanh = hướng dẫn, đỏ = lỗi)
    _pill = [UIView new];
    _pill.layer.cornerRadius = 12;
    _pill.layer.borderWidth = 1;
    [_card addSubview:_pill];
    _pillIcon = [UIImageView new];
    _pillIcon.contentMode = UIViewContentModeScaleAspectFit;
    [_pill addSubview:_pillIcon];
    _msg = [UILabel new];
    _msg.numberOfLines = 0;
    _msg.font = [UIFont systemFontOfSize:13 weight:UIFontWeightMedium];
    [_pill addSubview:_msg];

    // Ô nhập key
    _tf = [UITextField new];
    _tf.delegate = self;
    _tf.backgroundColor = [UIColor colorWithWhite:1 alpha:0.06];
    _tf.layer.cornerRadius = 14;
    _tf.layer.borderWidth = 1;
    _tf.layer.borderColor = [blue colorWithAlphaComponent:0.35].CGColor;
    _tf.textColor = UIColor.whiteColor;
    _tf.tintColor = blue;
    _tf.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightSemibold];
    _tf.attributedPlaceholder = [[NSAttributedString alloc] initWithString:@"QDONENLITE-XXX-XXXX-XXX"
        attributes:@{NSForegroundColorAttributeName: [UIColor colorWithWhite:1 alpha:0.3]}];
    // Tắt các tính năng gõ thông minh (gây giật và làm đổi dấu gạch ngang)
    _tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
    _tf.autocorrectionType = UITextAutocorrectionTypeNo;
    _tf.spellCheckingType = UITextSpellCheckingTypeNo;
    _tf.smartDashesType = UITextSmartDashesTypeNo;
    _tf.smartQuotesType = UITextSmartQuotesTypeNo;
    _tf.smartInsertDeleteType = UITextSmartInsertDeleteTypeNo;
    _tf.inputAssistantItem.leadingBarButtonGroups = @[];
    _tf.inputAssistantItem.trailingBarButtonGroups = @[];
    _tf.keyboardAppearance = UIKeyboardAppearanceDark;
    _tf.returnKeyType = UIReturnKeyGo;
    _tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    UIImageView *ic = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"key.fill"]];
    ic.tintColor = blue;
    ic.contentMode = UIViewContentModeCenter;
    ic.frame = CGRectMake(0, 0, 42, 50);
    _tf.leftView = ic;
    _tf.leftViewMode = UITextFieldViewModeAlways;
    [_tf addTarget:self action:@selector(fieldChanged) forControlEvents:UIControlEventEditingChanged];
    [_card addSubview:_tf];

    // Nút kích hoạt
    _btn = [UIButton buttonWithType:UIButtonTypeCustom];
    _btn.layer.cornerRadius = 14;
    _btn.layer.shadowColor = blue.CGColor;
    _btn.layer.shadowOpacity = 0.55;
    _btn.layer.shadowRadius = 10;
    _btn.layer.shadowOffset = CGSizeMake(0, 4);
    _btnGrad = [CAGradientLayer layer];
    _btnGrad.colors = @[(id)[UIColor colorWithRed:0.22 green:0.72 blue:1.0 alpha:1].CGColor,
                        (id)[UIColor colorWithRed:0.05 green:0.35 blue:0.95 alpha:1].CGColor];
    _btnGrad.startPoint = CGPointMake(0, 0);
    _btnGrad.endPoint = CGPointMake(1, 1);
    _btnGrad.cornerRadius = 14;
    [_btn.layer insertSublayer:_btnGrad atIndex:0];
    [_btn setAttributedTitle:[self btnTitle] forState:UIControlStateNormal];
    [_btn addTarget:self action:@selector(submit) forControlEvents:UIControlEventTouchUpInside];
    [_btn addTarget:self action:@selector(btnDown) forControlEvents:UIControlEventTouchDown];
    [_btn addTarget:self action:@selector(btnUp) forControlEvents:UIControlEventTouchUpInside | UIControlEventTouchUpOutside | UIControlEventTouchCancel];
    [_card addSubview:_btn];

    _spin = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spin.color = UIColor.whiteColor;
    _spin.hidesWhenStopped = YES;
    [_btn addSubview:_spin];

    _foot = [UILabel new];
    _foot.text = @"QDONENLITE rất hân hạnh khi hỗ trợ bạn";
    _foot.textAlignment = NSTextAlignmentCenter;
    _foot.font = [UIFont systemFontOfSize:11];
    _foot.textColor = [UIColor colorWithWhite:1 alpha:0.4];
    [_card addSubview:_foot];

    [self applyStyle];

    NSNotificationCenter *nc = NSNotificationCenter.defaultCenter;
    [nc addObserver:self selector:@selector(kbChange:) name:UIKeyboardWillChangeFrameNotification object:nil];
    [nc addObserver:self selector:@selector(kbHide:) name:UIKeyboardWillHideNotification object:nil];
}

- (void)dealloc { [NSNotificationCenter.defaultCenter removeObserver:self]; }

- (void)viewDidAppear:(BOOL)animated {
    [super viewDidAppear:animated];
    _card.transform = CGAffineTransformMakeScale(0.92, 0.92);
    _card.alpha = 0;
    [UIView animateWithDuration:0.35 delay:0 usingSpringWithDamping:0.82 initialSpringVelocity:0.5
                        options:0 animations:^{ self->_card.transform = CGAffineTransformIdentity; self->_card.alpha = 1; }
                     completion:nil];
}

- (void)viewDidLayoutSubviews { [super viewDidLayoutSubviews]; [self layoutCard]; }

// Có 3 kiểu bố cục: dọc (điện thoại đứng), 2 cột (nằm ngang), gọn (khi bàn phím che nhiều)
- (void)layoutCard {
    if (!_card) return;
    CGFloat W = self.view.bounds.size.width, H = self.view.bounds.size.height;
    if (W < 100 || H < 100) return;
    UIEdgeInsets sa = self.view.safeAreaInsets;
    CGFloat top = sa.top + 8;
    CGFloat bottom = _kb > 0 ? 8 : MAX(sa.bottom, 8);
    CGFloat availH = H - _kb - top - bottom;
    BOOL dense = availH < 270;
    BOOL wide = !dense && W > H;
    CGFloat pad = dense ? 14 : 22, gap = dense ? 8 : 14, fh = dense ? 46 : 52;

    _logoWrap.hidden = _title.hidden = _tag.hidden = _foot.hidden = dense;
    _divider.hidden = !wide;

    CGFloat cw, fx, fw, lw = 0;
    if (wide) { cw = MIN(640, W - 40); lw = floor(cw * 0.38); fx = lw + 14; fw = cw - fx - pad; }
    else { cw = MIN(dense ? 440 : 360, W - 32); fx = pad; fw = cw - 2 * pad; }

    CGSize ms = [_msg sizeThatFits:CGSizeMake(fw - 48, CGFLOAT_MAX)];
    CGFloat ph = MAX(36, ceil(ms.height) + 18);
    CGFloat formH = ph + gap + fh + gap + fh + (dense ? 0 : 26);
    CGFloat logoS = wide ? 84 : 88;
    CGFloat brandH = dense ? 0 : (logoS + 10 + 32 + 4 + 14);
    CGFloat contentH = wide ? MAX(formH, brandH) : (dense ? 0 : brandH + 20) + formH;
    CGFloat ch = contentH + 2 * pad;

    CGFloat formY = wide ? pad + (contentH - formH) / 2 : pad + (dense ? 0 : brandH + 20);
    if (!dense) {
        CGFloat bx = wide ? 0 : pad, bw = wide ? lw : cw - 2 * pad;
        CGFloat by = wide ? pad + (contentH - brandH) / 2 : pad;
        _logoWrap.frame = CGRectMake(bx + (bw - logoS) / 2, by, logoS, logoS);
        _logoWrap.layer.cornerRadius = logoS / 2;
        _logoWrap.layer.shadowPath = [UIBezierPath bezierPathWithOvalInRect:_logoWrap.bounds].CGPath;
        _logo.frame = CGRectInset(_logoWrap.bounds, 4, 4);
        _logo.layer.cornerRadius = _logo.bounds.size.width / 2;
        _title.frame = CGRectMake(bx + 6, by + logoS + 10, bw - 12, 32);
        _tag.frame = CGRectMake(bx + 6, by + logoS + 10 + 32 + 4, bw - 12, 14);
        _divider.frame = CGRectMake(lw, pad + 6, 1, ch - 2 * pad - 12);
    }

    CGFloat y = formY;
    _pill.frame = CGRectMake(fx, y, fw, ph);
    _pillIcon.frame = CGRectMake(11, (ph - 18) / 2, 18, 18);
    _msg.frame = CGRectMake(38, 9, fw - 48, ph - 18);
    y += ph + gap;
    _tf.frame = CGRectMake(fx, y, fw, fh); y += fh + gap;
    _btn.frame = CGRectMake(fx, y, fw, fh);
    _btnGrad.frame = _btn.bounds;
    _btn.layer.shadowPath = [UIBezierPath bezierPathWithRoundedRect:_btn.bounds cornerRadius:14].CGPath;
    _spin.center = CGPointMake(fw / 2, fh / 2);
    ((UIImageView *)_tf.leftView).frame = CGRectMake(0, 0, 42, fh);
    if (!dense) _foot.frame = CGRectMake(fx, y + fh + 10, fw, 14);

    CGFloat cy = ch >= availH ? top : top + (availH - ch) / 2;
    CGAffineTransform tr = _card.transform;
    _card.transform = CGAffineTransformIdentity;
    _card.frame = CGRectMake((W - cw) / 2, cy, cw, ch);
    _card.transform = tr;
    _cardGrad.frame = _card.bounds;
    _card.layer.shadowPath = [UIBezierPath bezierPathWithRoundedRect:_card.bounds cornerRadius:26].CGPath;
}

- (void)kbChange:(NSNotification *)n {
    CGRect f = [self.view convertRect:[n.userInfo[UIKeyboardFrameEndUserInfoKey] CGRectValue] fromView:nil];
    _kb = MAX(0, self.view.bounds.size.height - f.origin.y);
    [self animateLayout:n];
}
- (void)kbHide:(NSNotification *)n { _kb = 0; [self animateLayout:n]; }
- (void)animateLayout:(NSNotification *)n {
    NSTimeInterval d = [n.userInfo[UIKeyboardAnimationDurationUserInfoKey] doubleValue] ?: 0.25;
    [UIView animateWithDuration:d animations:^{ [self layoutCard]; }];
}

- (void)btnDown { [UIView animateWithDuration:0.1 animations:^{ self->_btn.transform = CGAffineTransformMakeScale(0.97, 0.97); self->_btn.alpha = 0.85; }]; }
- (void)btnUp { [UIView animateWithDuration:0.15 animations:^{ self->_btn.transform = CGAffineTransformIdentity; self->_btn.alpha = 1; }]; }

// Gõ phím: chỉ động tới giao diện đúng 1 lần (khi đang hiện lỗi), còn lại không làm gì để gõ mượt
- (void)fieldChanged {
    if (_err) [self showMessage:kPromptHint error:NO];
}
- (void)textFieldDidBeginEditing:(UITextField *)t { t.layer.borderColor = [QDKeyVC blue].CGColor; }
- (void)textFieldDidEndEditing:(UITextField *)t { t.layer.borderColor = [[QDKeyVC blue] colorWithAlphaComponent:0.35].CGColor; }
- (BOOL)textFieldShouldReturn:(UITextField *)t { [self submit]; return NO; }

- (void)applyStyle {
    UIColor *c = _err ? [QDKeyVC red] : [QDKeyVC blue];
    _pill.backgroundColor = [c colorWithAlphaComponent:0.12];
    _pill.layer.borderColor = [c colorWithAlphaComponent:0.35].CGColor;
    _pillIcon.tintColor = c;
    _pillIcon.image = [UIImage systemImageNamed:_err ? @"exclamationmark.triangle.fill" : @"info.circle.fill"];
    _msg.textColor = _err ? [UIColor colorWithRed:1 green:0.72 blue:0.73 alpha:1]
                          : [UIColor colorWithRed:0.78 green:0.87 blue:1 alpha:1];
}

- (void)showMessage:(NSString *)m error:(BOOL)err {
    [self loadViewIfNeeded];
    _err = err;
    _msg.text = m;
    [self applyStyle];
    [self layoutCard];
    if (err) {
        CAKeyframeAnimation *k = [CAKeyframeAnimation animationWithKeyPath:@"transform.translation.x"];
        k.values = @[@0, @-9, @9, @-6, @6, @-3, @3, @0];
        k.duration = 0.4;
        [_card.layer addAnimation:k forKey:@"shake"];
    }
}

- (void)setBusy:(BOOL)b {
    [self loadViewIfNeeded];
    _busy = b;
    _btn.enabled = !b;
    _tf.enabled = !b;
    [_btn setAttributedTitle:b ? [[NSAttributedString alloc] initWithString:@""] : [self btnTitle] forState:UIControlStateNormal];
    if (b) [_spin startAnimating]; else [_spin stopAnimating];
}

- (void)submit {
    if (_busy) return;
    NSString *key = QDNormKey(_tf.text);
    if (!key.length) { [self showMessage:@"Vui lòng nhập key" error:YES]; return; }
    _tf.text = key;
    [self.view endEditing:YES];
    [self setBusy:YES];
    [self showMessage:@"Đang kiểm tra key…" error:NO];
    if (self.onSubmit) self.onSubmit(key);
}

@end

static QDKeyVC *gKeyVC;

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
    if (!saved.length) { [self promptWithMessage:kPromptHint]; return; }
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
        @"bad_nonce": @"Phản hồi từ server không hợp lệ (mã E1)",
        @"bad_sig": @"Phản hồi từ server không hợp lệ (mã E2)",
        @"bad_time": @"Giờ trên máy không đúng, hãy bật cập nhật giờ tự động",
    };
    return m[err] ?: @"Lỗi kích hoạt";
}

+ (void)promptWithMessage:(NSString *)msg {
    BOOL isErr = ![msg isEqualToString:kPromptHint];
    if (gKeyVC) { // đang hiện sẵn: chỉ cập nhật thông báo
        gPrompting = YES;
        [gKeyVC setBusy:NO];
        [gKeyVC showMessage:msg error:isErr];
        return;
    }
    UIViewController *top = QDTop();
    if (!top) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ [self promptWithMessage:msg]; });
        return;
    }
    gPrompting = YES;
    QDKeyVC *vc = [QDKeyVC new];
    vc.modalPresentationStyle = UIModalPresentationOverFullScreen;
    vc.modalTransitionStyle = UIModalTransitionStyleCrossDissolve;
    [vc showMessage:msg error:isErr];
    vc.onSubmit = ^(NSString *key) {
        QDCall(@"/api/activate", key, ^(BOOL ok, NSString *err, long long exp, long long st) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) {
                    [[NSUserDefaults standardUserDefaults] setObject:QDNormKey(key) forKey:kSavedKey];
                    gGranted = YES;
                    gCurKey = QDNormKey(key);
                    [self scheduleExpiry:exp serverTime:st];
                    [gKeyVC dismissViewControllerAnimated:YES completion:^{
                        gKeyVC = nil;
                        gPrompting = NO;
                        [self granted];
                    }];
                } else {
                    [gKeyVC setBusy:NO];
                    [gKeyVC showMessage:[self text:err] error:YES];
                }
            });
        });
    };
    gKeyVC = vc;
    [top presentViewController:vc animated:YES completion:nil];
}

@end
