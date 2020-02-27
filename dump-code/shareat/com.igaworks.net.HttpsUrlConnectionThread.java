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
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map.Entry;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpsUrlConnectionThread extends Thread {
    public static final int GET = 0;
    public static final int POST = 1;
    private static final String TAG = "HttpsUrlConnectionThread";
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
    private HashMap<String, String> params;
    private String url = "";

    public HttpsUrlConnectionThread(Context context2, int method2, String url_, HashMap<String, String> params2, HttpCallbackListener listener2, boolean isEncode2, boolean callbackOnMainThread_) {
        this.url = url_;
        this.method = method2;
        this.params = params2;
        this.listener = listener2;
        this.context = context2;
        this.isEncode = isEncode2;
        this.callbackOnMainThread = callbackOnMainThread_;
    }

    public void run() {
        String apiName;
        try {
            Handler handler = new Handler(this.context.getMainLooper());
            String response = "";
            if (this.method == 0) {
                String queryString = getPostDataString(this.params);
                if (!this.url.contains("?")) {
                    this.url += "?";
                } else {
                    this.url += "&";
                }
                if (this.isEncode) {
                    this.url += "queryString=" + IgawBase64.encodeString(queryString);
                } else {
                    this.url += queryString;
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
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpsUrlConnectionThread: getPromotionInfo > url = " + this.url, 3, true);
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpsUrlConnectionThread: HTTP GET >> responseCode: " + responseCode, 0, false);
                    response = "";
                }
            } else {
                URL urlObj = new URL(this.url);
                String path = urlObj.getPath();
                try {
                    if (!path.contains("/") || path.lastIndexOf("/") >= path.length() - 1) {
                        apiName = path;
                    } else {
                        apiName = path.substring(path.lastIndexOf("/") + 1);
                    }
                } catch (Exception e) {
                    apiName = path;
                }
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpsUrlConnectionThread: HTTP POST > reqName : " + apiName + ", param size: " + this.params.size(), 3, true);
                if (this.isEncode) {
                    String queryString2 = getPostDataString(this.params);
                    this.params.clear();
                    this.params.put("queryString", IgawBase64.encodeString(queryString2));
                }
                this.conn = (HttpURLConnection) urlObj.openConnection();
                if (this.url.startsWith(CommonProtocol.URL_SCHEME)) {
                    ((HttpsURLConnection) this.conn).setHostnameVerifier(getTrustedVerifier());
                    ((HttpsURLConnection) this.conn).setSSLSocketFactory(getTrustedFactory());
                }
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
                this.conn.setRequestMethod(HttpRequest.METHOD_POST);
                this.conn.setDoInput(true);
                this.conn.setDoOutput(true);
                this.conn.setRequestProperty("Accept-Charset", "UTF-8");
                this.conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
                this.conn.setInstanceFollowRedirects(false);
                disableConnectionReuseIfNecessary();
                OutputStream os = this.conn.getOutputStream();
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
                writer.write(getPostDataString(this.params));
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpsUrlConnectionThread: HTTP POST >> responseCode: " + responseCode2, 0, false);
                    response = "";
                }
            }
            this.httpResponseString = response;
            if (this.httpResponseString == null || this.httpResponseString.equals("")) {
                if (this.callbackOnMainThread) {
                    handler.post(new Runnable() {
                        public void run() {
                            HttpsUrlConnectionThread.this.listener.callback(null);
                        }
                    });
                } else {
                    this.listener.callback(null);
                }
            } else if (this.callbackOnMainThread) {
                handler.post(new Runnable() {
                    public void run() {
                        if (CommonFrameworkImpl.isTest) {
                            IgawLogger.Logging(HttpsUrlConnectionThread.this.context, "Live", HttpsUrlConnectionThread.this.httpResponseString, 3, true);
                        }
                        HttpsUrlConnectionThread.this.listener.callback(HttpsUrlConnectionThread.this.httpResponseString);
                    }
                });
            } else {
                if (CommonFrameworkImpl.isTest) {
                    IgawLogger.Logging(this.context, "Live", this.httpResponseString, 3, true);
                }
                this.listener.callback(this.httpResponseString);
            }
            if (this.conn != null) {
                this.conn.disconnect();
            }
        } catch (Exception e2) {
            IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "Exception : " + e2.getMessage(), 0);
            if (this.callbackOnMainThread) {
                new Handler(this.context.getMainLooper()).post(new Runnable() {
                    public void run() {
                        HttpsUrlConnectionThread.this.listener.callback(null);
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

    private String getPostDataString(HashMap<String, String> params2) throws UnsupportedEncodingException {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (Entry<String, String> entry : params2.entrySet()) {
            if (first) {
                first = false;
            } else {
                result.append("&");
            }
            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            String value = entry.getValue();
            if (value == null) {
                value = "";
            }
            result.append(URLEncoder.encode(value, "UTF-8"));
        }
        return result.toString();
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
                Log.e(IgawConstant.QA_TAG, "HttpsUrlConnection > SSL Error: " + e.getMessage());
            }
        }
        return TRUSTED_FACTORY;
    }
}