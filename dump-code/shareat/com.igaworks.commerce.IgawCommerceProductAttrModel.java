package com.igaworks.commerce;

import android.content.Context;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import java.util.Map;
import java.util.TreeMap;

public class IgawCommerceProductAttrModel extends IgawCommerceProductModel {
    private static Context context;
    String[] key = new String[5];
    String[] value = new String[5];

    protected IgawCommerceProductAttrModel() {
    }

    public IgawCommerceProductAttrModel(Map<String, String> attrData) {
        if (attrData != null) {
            try {
                if (context == null) {
                    context = CommonFrameworkImpl.getContext();
                }
                if (context == null) {
                    Log.e(IgawConstant.QA_TAG, "eventFired >> Context is null. check start session is called.");
                }
                int i = 0;
                for (String key2 : new TreeMap<>(attrData).keySet()) {
                    this.key[i] = key2;
                    this.value[i] = attrData.get(key2);
                    i++;
                    if (i > 4) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceProductAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        return;
                    }
                }
            } catch (Exception e) {
            }
        }
    }

    public static IgawCommerceProductAttrModel create(Map<String, String> attrData) {
        return new IgawCommerceProductAttrModel(attrData);
    }
}