export TARGET = iphone:clang:latest:14.0
export ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QDLicense
QDLicense_FILES = QDLicense.m
QDLicense_FRAMEWORKS = UIKit Foundation
QDLicense_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
