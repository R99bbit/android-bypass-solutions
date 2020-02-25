package com.embrain.panelbigdata.network;

import com.embrain.panelbigdata.Vo.location.LocationGpsListRequest;
import com.embrain.panelbigdata.Vo.location.LocationGpsRequest;
import com.embrain.panelbigdata.Vo.location.LocationInsertRequest;
import com.embrain.panelbigdata.Vo.push.BigdataSessionListRequest;
import com.embrain.panelbigdata.Vo.push.BigdataSessionRequest;
import com.embrain.panelbigdata.Vo.token.RegistTokenRequest;
import com.embrain.panelbigdata.Vo.usage.UsageInsertRequest;
import com.embrain.panelbigdata.utils.LogUtil;
import com.google.gson.Gson;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.Callback;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;

public class HttpManager {
    private static OkHttpClient mClient;
    private static HttpManager mInstance;

    public static HttpManager getInstance() {
        if (mInstance == null) {
            mInstance = new HttpManager();
        }
        return mInstance;
    }

    private HttpManager() {
        getClient();
    }

    private static OkHttpClient getClient() {
        if (mClient == null) {
            Builder builder = new Builder();
            builder.connectTimeout(900000, TimeUnit.MILLISECONDS);
            builder.readTimeout(900000, TimeUnit.MILLISECONDS);
            mClient = builder.build();
        }
        return mClient;
    }

    private static SSLSocketFactory getSSLSocketFactory() {
        TrustManager[] trustManagerArr = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        }};
        try {
            SSLContext instance = SSLContext.getInstance("SSL");
            instance.init(null, trustManagerArr, new SecureRandom());
            return instance.getSocketFactory();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    static Headers getHeaders() {
        return new Headers.Builder().add("Accept", "application/json, text/plain, */*").add("Content-Type", "application/json;charset=UTF-8").build();
    }

    public void sendBigdataSession(BigdataSessionRequest bigdataSessionRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendBigdataSession() : ");
        sb.append(new Gson().toJson((Object) bigdataSessionRequest));
        LogUtil.write(sb.toString());
        APIs.sendBigdataSession(getClient(), bigdataSessionRequest, callback);
    }

    public void sendBigdataSessionList(BigdataSessionListRequest bigdataSessionListRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendBigdataSession() : ");
        sb.append(new Gson().toJson((Object) bigdataSessionListRequest));
        LogUtil.write(sb.toString());
        APIs.sendBigdataSessionList(getClient(), bigdataSessionListRequest, callback);
    }

    public void sendUsageInfo(UsageInsertRequest usageInsertRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendUsageInfo(): ");
        sb.append(new Gson().toJson((Object) usageInsertRequest));
        LogUtil.write(sb.toString());
        APIs.sendUsageInfo(getClient(), usageInsertRequest, callback);
    }

    public void sendGpsState(LocationGpsRequest locationGpsRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendGpsState(): ");
        sb.append(new Gson().toJson((Object) locationGpsRequest));
        LogUtil.write(sb.toString());
        APIs.sendGpsState(getClient(), locationGpsRequest, callback);
    }

    public void sendGpsStateList(LocationGpsListRequest locationGpsListRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendGpsStateList(): ");
        sb.append(new Gson().toJson((Object) locationGpsListRequest));
        LogUtil.write(sb.toString());
        APIs.sendGpsStateList(getClient(), locationGpsListRequest, callback);
    }

    public void sendLocationInfo(LocationInsertRequest locationInsertRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendLocationInfo(): ");
        sb.append(new Gson().toJson((Object) locationInsertRequest));
        LogUtil.write(sb.toString());
        APIs.sendLoacationInfo(getClient(), locationInsertRequest, callback);
    }

    public void sendToken(RegistTokenRequest registTokenRequest, Callback callback) {
        StringBuilder sb = new StringBuilder();
        sb.append("request sendToken(): ");
        sb.append(new Gson().toJson((Object) registTokenRequest));
        LogUtil.write(sb.toString());
        APIs.sendToken(getClient(), registTokenRequest, callback);
    }
}