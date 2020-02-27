package com.igaworks.net;

import android.content.Context;
import android.os.Build.VERSION;
import android.os.Handler;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.HttpCallbackListener;
import com.igaworks.util.IgawBase64;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;

@Deprecated
public class DeeplinkHttpUrlConnectionThread extends Thread {
    public static final int GET = 0;
    public static final int POST = 1;
    private static final String TAG = "JSONHttpUrlConnectionThread";
    private boolean callbackOnMainThread;
    private HttpURLConnection conn;
    /* access modifiers changed from: private */
    public Context context;
    /* access modifiers changed from: private */
    public String httpResponseString;
    private boolean isEncode;
    /* access modifiers changed from: private */
    public HttpCallbackListener listener;
    private int method;
    private String queryString;
    private String url;

    @Deprecated
    public DeeplinkHttpUrlConnectionThread(Context context2, int method2, String url_, String queryString2, HttpCallbackListener listener2) {
        this(context2, method2, url_, queryString2, listener2, false, true);
    }

    public DeeplinkHttpUrlConnectionThread(Context context2, int method2, String url_, String queryString2, HttpCallbackListener listener2, boolean isEncode2, boolean callbackOnMainThread_) {
        this.url = "";
        this.httpResponseString = "";
        this.callbackOnMainThread = true;
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
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
                this.conn.setRequestMethod(HttpRequest.METHOD_GET);
                this.conn.setRequestProperty("Accept-Charset", "UTF-8");
                this.conn.setDoInput(true);
                this.conn.setDoOutput(true);
                this.conn.setInstanceFollowRedirects(false);
                disableConnectionReuseIfNecessary();
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JSONHttpUrlConnectionThread>> url = " + this.url, 3, true);
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JSONHttpUrlConnectionThread: HTTP GET >> responseCode: " + responseCode, 0, false);
                    response = "";
                }
            } else {
                URL urlObj = new URL(this.url);
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JSONHttpUrlConnectionThread: HTTP POST > reqName : " + this.url + ", param : " + this.queryString, 3, true);
                this.conn = (HttpURLConnection) urlObj.openConnection();
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "JSONHttpUrlConnectionThread: HTTP POST >> responseCode: " + responseCode2, 0, false);
                    response = "";
                }
            }
            this.httpResponseString = response;
            if (this.httpResponseString == null || this.httpResponseString.equals("")) {
                if (this.callbackOnMainThread) {
                    handler.post(new Runnable() {
                        public void run() {
                            DeeplinkHttpUrlConnectionThread.this.listener.callback(null);
                        }
                    });
                } else {
                    this.listener.callback(null);
                }
            } else if (this.callbackOnMainThread) {
                handler.post(new Runnable() {
                    public void run() {
                        DeeplinkHttpUrlConnectionThread.this.listener.callback(DeeplinkHttpUrlConnectionThread.this.httpResponseString);
                        if (CommonFrameworkImpl.isTest) {
                            IgawLogger.Logging(DeeplinkHttpUrlConnectionThread.this.context, "Live", DeeplinkHttpUrlConnectionThread.this.httpResponseString, 3, true);
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
                        DeeplinkHttpUrlConnectionThread.this.listener.callback(null);
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
}