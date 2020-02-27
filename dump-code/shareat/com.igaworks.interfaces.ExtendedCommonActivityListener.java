package com.igaworks.interfaces;

import android.content.Context;

public interface ExtendedCommonActivityListener extends CommonActivityListener {
    void onEndSession(Context context, int i);
}