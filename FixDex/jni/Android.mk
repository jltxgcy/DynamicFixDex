LOCAL_PATH := $(call my-dir)
  
include $(CLEAR_VARS)  
  
LOCAL_MODULE    := findcode  
  
LOCAL_SRC_FILES := findcode.cpp

LOCAL_LDLIBS    := -llog -ldl
        
include $(BUILD_SHARED_LIBRARY)