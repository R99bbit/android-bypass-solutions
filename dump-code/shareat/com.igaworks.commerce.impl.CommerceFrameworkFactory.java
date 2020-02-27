package com.igaworks.commerce.impl;

import com.igaworks.commerce.interfaces.CommerceInterface;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.CommonActivityListener;
import com.igaworks.interfaces.ExtendedCommonActivityListener;

public class CommerceFrameworkFactory {
    private static CommerceInterface singleton = new CommerceImpl();

    static {
        if (singleton == null) {
        }
        CommonFrameworkImpl.addActivityListener("Commerce", (CommonActivityListener) singleton);
        CommonFrameworkImpl.addExtendedActivityListener("Commerce_EndSession", (ExtendedCommonActivityListener) singleton);
    }

    public static CommerceInterface getFramework() {
        if (singleton == null) {
            singleton = new CommerceImpl();
        }
        return singleton;
    }
}