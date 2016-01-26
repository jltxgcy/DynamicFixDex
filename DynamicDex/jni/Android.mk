LOCAL_PATH := $(call my-dir)
  
include $(CLEAR_VARS)  
  
LOCAL_MODULE    := dexloader  
  
LOCAL_SRC_FILES := dynamicdex.cpp

LOCAL_LDLIBS    := -llog -ldl
        
include $(BUILD_SHARED_LIBRARY)