package com.embrain.panelpower.networks;

import java.io.IOException;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.Response;

public class PanelPowerInterceptor implements Interceptor {
    private static final String TAG = "PanelPowerInterceptor";

    public Response intercept(Chain chain) throws IOException {
        return chain.proceed(chain.request().newBuilder().build());
    }
}