package com.embrain.panelbigdata.network;

import android.util.Log;
import java.io.IOException;
import okhttp3.Interceptor;
import okhttp3.Interceptor.Chain;
import okhttp3.Request;
import okhttp3.Response;

public class PanelPowerInterceptor implements Interceptor {
    private static final String TAG = "PanelPowerInterceptor";

    public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        String str = TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("interceptor(request) : method = ");
        sb.append(request.method());
        Log.d(str, sb.toString());
        String str2 = TAG;
        StringBuilder sb2 = new StringBuilder();
        sb2.append("interceptor(request) : url = ");
        sb2.append(request.headers());
        Log.d(str2, sb2.toString());
        String str3 = TAG;
        StringBuilder sb3 = new StringBuilder();
        sb3.append("interceptor(request) : connection = ");
        sb3.append(chain.connection());
        Log.d(str3, sb3.toString());
        Response proceed = chain.proceed(request);
        String str4 = TAG;
        StringBuilder sb4 = new StringBuilder();
        sb4.append("interceptor(response) : url = ");
        sb4.append(proceed.request().url());
        Log.d(str4, sb4.toString());
        String str5 = TAG;
        StringBuilder sb5 = new StringBuilder();
        sb5.append("interceptor(response) : header = ");
        sb5.append(proceed.headers());
        Log.d(str5, sb5.toString());
        return proceed;
    }
}