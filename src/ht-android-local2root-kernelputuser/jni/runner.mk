LOCAL_PATH := $(call my-dir)
CPP_CORE := $(abspath $(call my-dir)/../../CPPCore)

include $(CLEAR_VARS)

LOCAL_MODULE    := runner
LOCAL_SRC_FILES := suidext/runner.c utils/deobfuscate.c utils/ps.c
LOCAL_ARM_MODE := arm
LOCAL_CFLAGS := -g
LOCAL_C_INCLUDES += headers
include $(BUILD_EXECUTABLE)
