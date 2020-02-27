package com.igaworks.adbrix.impl;

import com.igaworks.adbrix.interfaces.ADBrixInterface;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.CommonActivityListener;
import com.igaworks.interfaces.ExtendedCommonActivityListener;

public class ADBrixFrameworkFactory {
    private static ADBrixInterface singleton = new ADBrixFrameworkImpl();

    static {
        if (singleton == null) {
        }
        CommonFrameworkImpl.addActivityListener("ADBrix", (CommonActivityListener) singleton);
        CommonFrameworkImpl.addExtendedActivityListener("ADBrix_OnEndSession", (ExtendedCommonActivityListener) singleton);
    }

    public static ADBrixInterface getFramework() {
        if (singleton == null) {
            singleton = new ADBrixFrameworkImpl();
        }
        return singleton;
    }
}