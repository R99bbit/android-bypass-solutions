package com.igaworks.net;

import android.content.Context;
import android.os.Build.VERSION;
import android.os.Handler;
import android.util.Log;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.HttpCallbackListener;
import com.igaworks.util.IgawBase64;
import com.kakao.util.helper.CommonProtocol;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class JsonHttpsUrlConnectionThread extends Thread {
    public static final int GET = 0;
    public static final int POST = 1;
    private static final String TAG = "JsonHttpsUrlConnectionThread";
    private static SSLSocketFactory TRUSTED_FACTORY;
    private static HostnameVerifier TRUSTED_VERIFIER;
    private boolean callbackOnMainThread = true;
    private HttpURLConnection conn;
    /* access modifiers changed from: private */
    public Context context;
    /* access modifiers changed from: private */
    public String httpResponseString = "";
    private boolean isEncode;
    /* access modifiers changed from: private */
    public HttpCallbackListener listener;
    private int method;
    private String queryString;
    private String url = "";

    public JsonHttpsUrlConnectionThread(Context context2, int method2, String url_, String queryString2, HttpCallbackListener listener2, boolean isEncode2, boolean callbackOnMainThread_) {
        this.url = url_;
        this.method = method2;
        this.queryString = queryString2;
        this.listener = listener2;
        this.context = context2;
        this.isEncode = isEncode2;
        this.callbackOnMainThread = callbackOnMainThread_;
    }

    public void run() {
        try {
            Handler handler = new Handler(this.context.getMainLooper());
            String response = "";
            if (this.method == 0) {
                if (!this.url.contains("?")) {
                    this.url += "?";
                } else {
                    this.url += "&";
                }
                if (this.isEncode) {
                    this.url += "queryString=" + IgawBase64.encodeString(this.queryString);
                } else {
                    this.url += this.queryString;
                }
                this.conn = (HttpURLConnection) new URL(this.url).openConnection();
                if (this.url.startsWith(CommonProtocol.URL_SCHEME)) {
                    ((HttpsURLConnection) this.conn).setHostnameVerifier(getTrustedVerifier());
                    ((HttpsURLConnection) this.conn).setSSLSocketFactory(getTrustedFactory());
                }
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
                this.conn.setRequestMethod(HttpRequest.METHOD_GET);
                this.conn.setRequestProperty("Accept-Charset", "UTF-8");
                this.conn.setDoInput(true);
                this.conn.setDoOutput(true);
                this.conn.setInstanceFollowRedirects(false);
                disableConnectionReuseIfNecessary();
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JsonHttpsUrlConnectionThread>> url = " + this.url, 3, true);
                int responseCode = this.conn.getResponseCode();
                if (responseCode == 200) {
                    BufferedReader br = new BufferedReader(new InputStreamReader(this.conn.getInputStream()));
                    while (true) {
                        String line = br.readLine();
                        if (line == null) {
                            break;
                        }
                        response = new StringBuilder(String.valueOf(response)).append(line).toString();
                    }
                } else {
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JsonHttpsUrlConnectionThread: HTTP GET >> responseCode: " + responseCode, 0, false);
                    response = "";
                }
            } else {
                URL urlObj = new URL(this.url);
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JsonHttpsUrlConnectionThread: HTTP POST > reqName : " + this.url + ", param : " + this.queryString, 3, true);
                this.conn = (HttpURLConnection) urlObj.openConnection();
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
                if (this.url.startsWith(CommonProtocol.URL_SCHEME)) {
                    ((HttpsURLConnection) this.conn).setHostnameVerifier(getTrustedVerifier());
                    ((HttpsURLConnection) this.conn).setSSLSocketFactory(getTrustedFactory());
                }
                this.conn.setRequestMethod(HttpRequest.METHOD_POST);
                this.conn.setDoInput(true);
                this.conn.setDoOutput(true);
                this.conn.setRequestProperty("Accept-Charset", "UTF-8");
                this.conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                this.conn.setInstanceFollowRedirects(false);
                disableConnectionReuseIfNecessary();
                OutputStream os = this.conn.getOutputStream();
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
                writer.write(this.queryString);
                writer.flush();
                writer.close();
                os.close();
                int responseCode2 = this.conn.getResponseCode();
                if (responseCode2 == 200) {
                    BufferedReader br2 = new BufferedReader(new InputStreamReader(this.conn.getInputStream()));
                    while (true) {
                        String line2 = br2.readLine();
                        if (line2 == null) {
                            break;
                        }
                        response = new StringBuilder(String.valueOf(response)).append(line2).toString();
                    }
                } else {
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JsonHttpsUrlConnectionThread: HTTP POST >> responseCode: " + responseCode2, 0, false);
                    response = "";
                }
            }
            this.httpResponseString = response;
            if (this.httpResponseString == null || this.httpResponseString.equals("")) {
                if (this.callbackOnMainThread) {
                    handler.post(new Runnable() {
                        public void run() {
                            JsonHttpsUrlConnectionThread.this.listener.callback(null);
                        }
                    });
                } else {
                    this.listener.callback(null);
                }
            } else if (this.callbackOnMainThread) {
                handler.post(new Runnable() {
                    public void run() {
                        JsonHttpsUrlConnectionThread.this.listener.callback(JsonHttpsUrlConnectionThread.this.httpResponseString);
                        if (CommonFrameworkImpl.isTest) {
                            IgawLogger.Logging(JsonHttpsUrlConnectionThread.this.context, "Live", JsonHttpsUrlConnectionThread.this.httpResponseString, 3, true);
                        }
                    }
                });
            } else {
                this.listener.callback(this.httpResponseString);
                if (CommonFrameworkImpl.isTest) {
                    IgawLogger.Logging(this.context, "Live", this.httpResponseString, 3, true);
                }
            }
            if (this.conn != null) {
                this.conn.disconnect();
            }
        } catch (Exception e) {
            IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "Exception : " + e.getMessage(), 0);
            Handler handler2 = new Handler(this.context.getMainLooper());
            if (this.callbackOnMainThread) {
                handler2.post(new Runnable() {
                    public void run() {
                        JsonHttpsUrlConnectionThread.this.listener.callback(null);
                    }
                });
            } else {
                this.listener.callback(null);
            }
            if (this.conn != null) {
                this.conn.disconnect();
            }
        } catch (Throwable th) {
            if (this.conn != null) {
                this.conn.disconnect();
            }
            throw th;
        }
    }

    private void disableConnectionReuseIfNecessary() {
        if (Integer.parseInt(VERSION.SDK) < 8) {
            System.setProperty("http.keepAlive", "false");
        }
    }

    private HostnameVerifier getTrustedVerifier() {
        if (TRUSTED_VERIFIER == null) {
            TRUSTED_VERIFIER = new HostnameVerifier() {
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            };
        }
        return TRUSTED_VERIFIER;
    }

    private SSLSocketFactory getTrustedFactory() {
        if (TRUSTED_FACTORY == null) {
            TrustManager[] trustAllCerts = {new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    try {
                        chain[0].checkValidity();
                    } catch (Exception e) {
                        throw new CertificateException("Certificate not valid or trusted.");
                    }
                }
            }};
            try {
                SSLContext context2 = SSLContext.getInstance("TLS");
                context2.init(null, trustAllCerts, new SecureRandom());
                TRUSTED_FACTORY = context2.getSocketFactory();
            } catch (GeneralSecurityException e) {
                Log.e(IgawConstant.QA_TAG, "JsonHttpsUrlConnection > SSL Error: " + e.getMessage());
            }
        }
        return TRUSTED_FACTORY;
    }
}