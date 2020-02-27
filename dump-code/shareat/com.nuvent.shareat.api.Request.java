package com.nuvent.shareat.api;

import android.content.Context;
import com.crashlytics.android.Crashlytics;
import com.loopj.android.http.AsyncHttpClient;
import com.loopj.android.http.AsyncHttpResponseHandler;
import com.loopj.android.http.RequestParams;
import com.nuvent.shareat.BuildConfig;
import com.nuvent.shareat.exception.NetworkException;
import com.nuvent.shareat.manager.app.SessionManager;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.File;
import java.io.FileNotFoundException;
import java.net.UnknownHostException;
import javax.net.ssl.SSLHandshakeException;
import org.apache.http.Header;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpResponseException;
import org.jboss.netty.channel.ConnectTimeoutException;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;

public abstract class Request {
    /* access modifiers changed from: private */
    public long completeTime;
    private Context context;
    /* access modifiers changed from: private */
    public String encoding = "UTF-8";
    private AsyncHttpClient httpClient;
    protected String method;
    /* access modifiers changed from: private */
    public RequestParams params = new RequestParams();
    private long requestTime;
    protected String serviceUrl;

    public static class RequestHandler {
        public void onStart() {
        }

        public void onProgress(int bytesWritten, int totalSize) {
        }

        public void onResult(Object result) {
        }

        public void onFailure(Exception exception) {
        }

        public void onFinish() {
        }
    }

    /* access modifiers changed from: protected */
    public abstract Object parseContent(Header[] headerArr, String str) throws Exception;

    /* access modifiers changed from: protected */
    public abstract Object parseErrorCode(String str) throws Exception;

    public Request(Context context2) {
        this.context = context2;
        this.httpClient = BuildConfig.FLAVOR.equals("develop") ? new AsyncHttpClient() : new AsyncHttpClient(true, 80, 443);
        this.httpClient.setTimeout(7000);
    }

    public void cancel() {
        this.httpClient.cancelRequests(this.context, true);
    }

    public void addHeader(String header, String value) {
        this.httpClient.addHeader(header, value);
    }

    public void addGetParam(String parameter) {
        this.serviceUrl += parameter;
    }

    public void addParam(String key, String value) {
        this.params.put(key, value);
    }

    public void addCookieStore(CookieStore store) {
        this.httpClient.setCookieStore(store);
    }

    public void addFile(String key, String path) {
        try {
            this.params.put(key, new File(path));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        this.httpClient.setTimeout(7000);
    }

    public long getElasedTime() {
        return this.completeTime - this.requestTime;
    }

    public String getEncoding() {
        return this.encoding;
    }

    public void setEncoding(String encoding2) {
        this.encoding = encoding2;
    }

    public void request(final RequestHandler requestHandler) {
        if (this.serviceUrl.equals(ApiUrl.ADDRESS_INFO) && this.method.equals(HttpRequest.METHOD_POST)) {
            this.httpClient.setTimeout(60000);
        }
        this.requestTime = System.currentTimeMillis();
        if (!SessionManager.getInstance().getAuthToken().isEmpty()) {
            addHeader("auth_token", SessionManager.getInstance().getAuthToken());
        }
        if (!SessionManager.getInstance().getSessionCookie().isEmpty()) {
            addHeader(Names.COOKIE, SessionManager.getInstance().getSessionCookie());
        }
        AsyncHttpResponseHandler handler = new AsyncHttpResponseHandler() {
            public void onStart() {
                if (requestHandler != null) {
                    requestHandler.onStart();
                }
            }

            public void onProgress(int bytesWritten, int totalSize) {
                if (requestHandler != null) {
                    requestHandler.onProgress(bytesWritten, totalSize);
                }
            }

            public void onSuccess(int statusCode, Header[] headers, byte[] responseBody) {
                Request.this.completeTime = System.currentTimeMillis();
                if (responseBody != null) {
                    try {
                        if (responseBody.length != 0) {
                            Object obj = Request.this.parseContent(headers, new String(responseBody, Request.this.encoding));
                            if (requestHandler != null) {
                                requestHandler.onResult(obj);
                                return;
                            }
                            return;
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        if (requestHandler != null) {
                            requestHandler.onFailure(e);
                            return;
                        }
                        return;
                    }
                }
                Object obj2 = Request.this.parseContent(headers, "");
                if (requestHandler != null) {
                    requestHandler.onResult(obj2);
                }
            }

            public void onFailure(int statusCode, Header[] headers, byte[] responseBody, Throwable error) {
                Request.this.completeTime = System.currentTimeMillis();
                String log = "serviceUrl :: " + Request.this.serviceUrl + " / statusCode :: " + statusCode + " / error :: " + error.getMessage() + " / params :: " + Request.this.params + " / method :: " + Request.this.method + " / responseBody :: " + (responseBody == null ? "null" : new String(responseBody));
                Crashlytics.getInstance();
                Crashlytics.log(log);
                Crashlytics.getInstance();
                Crashlytics.logException(new NetworkException(error, log));
                try {
                    if (error instanceof UnknownHostException) {
                        requestHandler.onFailure(new NetworkException());
                    } else if (error instanceof ConnectTimeoutException) {
                        requestHandler.onFailure(new ConnectTimeoutException());
                    } else if (error instanceof HttpResponseException) {
                        requestHandler.onFailure(new Exception(error));
                    } else if (error instanceof SSLHandshakeException) {
                        requestHandler.onFailure(new SSLHandshakeException(error.getMessage()));
                    } else if (error instanceof UnknownHostException) {
                        requestHandler.onFailure(new UnknownHostException());
                    } else {
                        requestHandler.onFailure(new NetworkException());
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    if (requestHandler != null) {
                        requestHandler.onFailure(e);
                    }
                }
            }

            public void onFinish() {
                if (requestHandler != null) {
                    requestHandler.onFinish();
                }
            }
        };
        if (this.method.equalsIgnoreCase(HttpRequest.METHOD_GET)) {
            this.httpClient.get(this.context, this.serviceUrl, this.params, handler);
        } else if (this.method.equalsIgnoreCase(HttpRequest.METHOD_POST)) {
            this.httpClient.post(this.context, this.serviceUrl, this.params, handler);
        } else if (this.method.equalsIgnoreCase(HttpRequest.METHOD_PUT)) {
            this.httpClient.put(this.context, this.serviceUrl, this.params, handler);
        } else if (this.method.equalsIgnoreCase(HttpRequest.METHOD_DELETE)) {
            this.httpClient.delete(this.context, this.serviceUrl, handler);
        } else if (this.method.equalsIgnoreCase(HttpRequest.METHOD_HEAD)) {
            this.httpClient.head(this.context, this.serviceUrl, this.params, handler);
        }
    }
}