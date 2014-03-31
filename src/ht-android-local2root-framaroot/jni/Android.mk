LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := runner
LOCAL_SRC_FILES := runner.c
LOCAL_LDLIBS    := -llog

include $(BUILD_SHARED_LIBRARY)

#include $(CLEAR_VARS)

#LOCAL_MODULE    := exploit
#LOCAL_SRC_FILES := exploit.c
#include $(BUILD_EXECUTABLE) 

include $(CLEAR_VARS)

LOCAL_MODULE    := suidext
LOCAL_SRC_FILES := suidext.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := expl_check
LOCAL_SRC_FILES := expl_check.c

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE    := local_exploit
LOCAL_SRC_FILES := local_exploit.c exploit_list.c kallsyms_in_memory.c kallsyms.c
LOCAL_C_INCLUDES := headers

include $(BUILD_EXECUTABLE)


