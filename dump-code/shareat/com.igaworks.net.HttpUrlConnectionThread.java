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
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map.Entry;

@Deprecated
public class HttpUrlConnectionThread extends Thread {
    public static final int GET = 0;
    public static final int POST = 1;
    private static final String TAG = "HttpUrlConnectionThread";
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
    private HashMap<String, String> params;
    private String url;

    public HttpUrlConnectionThread(Context context2, int method2, String url_, HashMap<String, String> params2, HttpCallbackListener listener2) {
        this(context2, method2, url_, params2, listener2, false, true);
    }

    @Deprecated
    public HttpUrlConnectionThread(Context context2, int method2, String url_, HashMap<String, String> params2, HttpCallbackListener listener2, boolean isEncode2) {
        this.url = "";
        this.httpResponseString = "";
        this.callbackOnMainThread = true;
        this.url = url_;
        this.method = method2;
        this.params = params2;
        this.listener = listener2;
        this.context = context2;
        this.isEncode = isEncode2;
    }

    public HttpUrlConnectionThread(Context context2, int method2, String url_, HashMap<String, String> params2, HttpCallbackListener listener2, boolean isEncode2, boolean callbackOnMainThread_) {
        this.url = "";
        this.httpResponseString = "";
        this.callbackOnMainThread = true;
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
                this.conn.setReadTimeout(15000);
                this.conn.setConnectTimeout(15000);
                this.conn.setRequestMethod(HttpRequest.METHOD_GET);
                this.conn.setRequestProperty("Accept-Charset", "UTF-8");
                this.conn.setDoInput(true);
                this.conn.setDoOutput(true);
                this.conn.setInstanceFollowRedirects(false);
                disableConnectionReuseIfNecessary();
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpUrlConnectionThread: getPromotionInfo > url = " + this.url, 3, true);
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpUrlConnectionThread: HTTP GET >> responseCode: " + responseCode, 0, false);
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
                IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpUrlConnectionThread: HTTP POST > reqName : " + apiName + ", param size: " + this.params.size(), 3, true);
                if (this.isEncode) {
                    String queryString2 = getPostDataString(this.params);
                    this.params.clear();
                    this.params.put("queryString", IgawBase64.encodeString(queryString2));
                }
                this.conn = (HttpURLConnection) urlObj.openConnection();
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
                    IgawLogger.Logging(this.context, IgawConstant.QA_TAG, "HttpUrlConnectionThread: HTTP POST >> responseCode: " + responseCode2, 0, false);
                    response = "";
                }
            }
            this.httpResponseString = response;
            if (this.httpResponseString == null || this.httpResponseString.equals("")) {
                if (this.callbackOnMainThread) {
                    handler.post(new Runnable() {
                        public void run() {
                            HttpUrlConnectionThread.this.listener.callback(null);
                        }
                    });
                } else {
                    this.listener.callback(null);
                }
            } else if (this.callbackOnMainThread) {
                handler.post(new Runnable() {
                    public void run() {
                        if (CommonFrameworkImpl.isTest) {
                            IgawLogger.Logging(HttpUrlConnectionThread.this.context, "Live", HttpUrlConnectionThread.this.httpResponseString, 3, true);
                        }
                        HttpUrlConnectionThread.this.listener.callback(HttpUrlConnectionThread.this.httpResponseString);
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
                        HttpUrlConnectionThread.this.listener.callback(null);
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
}