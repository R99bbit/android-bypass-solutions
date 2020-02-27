package com.igaworks.impl;

import com.igaworks.interfaces.CommonInterface;

public class CommonFrameworkFactory {
    public static boolean isHasAdbrixSDK = false;
    public static boolean isHasAdpopcornSDK = false;
    public static boolean isHasDisplayAdSDK = false;
    public static boolean isHasLiveOpsSDK = false;
    public static boolean isHasPlusLockSDK = false;
    private static CommonInterface singleton;

    public static CommonInterface getCommonFramework() {
        if (singleton == null) {
            singleton = new CommonFrameworkImpl() {
            };
        }
        try {
            Class.forName("com.igaworks.adbrix.IgawAdbrix");
            isHasAdbrixSDK = true;
        } catch (Exception e) {
            isHasAdbrixSDK = false;
        }
        try {
            Class.forName("com.igaworks.adbrix.impl.ADBrixFrameworkFactory");
            isHasAdbrixSDK = true;
        } catch (Exception e2) {
            isHasAdbrixSDK = false;
        }
        try {
            Class.forName("com.igaworks.liveops.pushservice.LiveOpsPushService");
            isHasLiveOpsSDK = true;
        } catch (Exception e3) {
            isHasLiveOpsSDK = false;
        }
        try {
            Class.forName("com.igaworks.commerce.impl.CommerceFrameworkFactory");
        } catch (Exception e4) {
        }
        try {
            Class.forName("com.igaworks.adpopcorn.IgawAdpopcorn");
            isHasAdpopcornSDK = true;
        } catch (Exception e5) {
            isHasAdpopcornSDK = false;
        }
        try {
            Class.forName("com.igaworks.adpopcorn.pluslock.IgawPlusLock");
            isHasPlusLockSDK = true;
        } catch (Exception e6) {
            isHasPlusLockSDK = false;
        }
        try {
            Class.forName("com.igaworks.displayad.IgawDisplayAd");
            isHasDisplayAdSDK = true;
        } catch (Exception e7) {
            isHasDisplayAdSDK = false;
        }
        return singleton;
    }
}