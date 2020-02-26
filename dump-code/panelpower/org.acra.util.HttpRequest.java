package org.acra.util;

import com.embrain.panelpower.IConstValue.SavedMoney;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map;
import org.acra.ACRA;
import org.acra.log.ACRALog;
import org.acra.sender.HttpSender.Method;
import org.acra.sender.HttpSender.Type;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

public final class HttpRequest {
    private int connectionTimeOut = 3000;
    private Map<String, String> headers;
    private String login;
    private int maxNrRetries = 3;
    private String password;
    private int socketTimeOut = 3000;

    /* renamed from: org.acra.util.HttpRequest$1 reason: invalid class name */
    static /* synthetic */ class AnonymousClass1 {
        static final /* synthetic */ int[] $SwitchMap$org$acra$sender$HttpSender$Method = new int[Method.values().length];

        /* JADX WARNING: Can't wrap try/catch for region: R(6:0|1|2|3|4|6) */
        /* JADX WARNING: Code restructure failed: missing block: B:7:?, code lost:
            return;
         */
        /* JADX WARNING: Failed to process nested try/catch */
        /* JADX WARNING: Missing exception handler attribute for start block: B:3:0x0014 */
        static {
            $SwitchMap$org$acra$sender$HttpSender$Method[Method.POST.ordinal()] = 1;
            $SwitchMap$org$acra$sender$HttpSender$Method[Method.PUT.ordinal()] = 2;
        }
    }

    private static class SocketTimeOutRetryHandler implements HttpRequestRetryHandler {
        private final HttpParams httpParams;
        private final int maxNrRetries;

        /* synthetic */ SocketTimeOutRetryHandler(HttpParams httpParams2, int i, AnonymousClass1 r3) {
            this(httpParams2, i);
        }

        private SocketTimeOutRetryHandler(HttpParams httpParams2, int i) {
            this.httpParams = httpParams2;
            this.maxNrRetries = i;
        }

        public boolean retryRequest(IOException iOException, int i, HttpContext httpContext) {
            if (iOException instanceof SocketTimeoutException) {
                if (i <= this.maxNrRetries) {
                    HttpParams httpParams2 = this.httpParams;
                    if (httpParams2 != null) {
                        int soTimeout = HttpConnectionParams.getSoTimeout(httpParams2) * 2;
                        HttpConnectionParams.setSoTimeout(this.httpParams, soTimeout);
                        ACRALog aCRALog = ACRA.log;
                        String str = ACRA.LOG_TAG;
                        StringBuilder sb = new StringBuilder();
                        sb.append("SocketTimeOut - increasing time out to ");
                        sb.append(soTimeout);
                        sb.append(" millis and trying again");
                        aCRALog.d(str, sb.toString());
                    } else {
                        ACRA.log.d(ACRA.LOG_TAG, "SocketTimeOut - no HttpParams, cannot increase time out. Trying again with current settings");
                    }
                    return true;
                }
                ACRALog aCRALog2 = ACRA.log;
                String str2 = ACRA.LOG_TAG;
                StringBuilder sb2 = new StringBuilder();
                sb2.append("SocketTimeOut but exceeded max number of retries : ");
                sb2.append(this.maxNrRetries);
                aCRALog2.d(str2, sb2.toString());
            }
            return false;
        }
    }

    public void setLogin(String str) {
        this.login = str;
    }

    public void setPassword(String str) {
        this.password = str;
    }

    public void setConnectionTimeOut(int i) {
        this.connectionTimeOut = i;
    }

    public void setSocketTimeOut(int i) {
        this.socketTimeOut = i;
    }

    public void setHeaders(Map<String, String> map) {
        this.headers = map;
    }

    public void setMaxNrRetries(int i) {
        this.maxNrRetries = i;
    }

    /* JADX INFO: finally extract failed */
    public void send(URL url, Method method, String str, Type type) throws IOException {
        HttpClient httpClient = getHttpClient();
        HttpEntityEnclosingRequestBase httpRequest = getHttpRequest(url, method, str, type);
        ACRALog aCRALog = ACRA.log;
        String str2 = ACRA.LOG_TAG;
        StringBuilder sb = new StringBuilder();
        sb.append("Sending request to ");
        sb.append(url);
        aCRALog.d(str2, sb.toString());
        HttpResponse httpResponse = null;
        try {
            HttpResponse execute = httpClient.execute(httpRequest, new BasicHttpContext());
            if (execute != null) {
                if (execute.getStatusLine() != null) {
                    String num = Integer.toString(execute.getStatusLine().getStatusCode());
                    if (!num.equals("409") && !num.equals("403")) {
                        if (num.startsWith("4") || num.startsWith(SavedMoney.GIVE_TP_TELCOIN)) {
                            StringBuilder sb2 = new StringBuilder();
                            sb2.append("Host returned error code ");
                            sb2.append(num);
                            throw new IOException(sb2.toString());
                        }
                    }
                }
                EntityUtils.toString(execute.getEntity());
            }
            if (execute != null) {
                execute.getEntity().consumeContent();
            }
        } catch (Throwable th) {
            if (httpResponse != null) {
                httpResponse.getEntity().consumeContent();
            }
            throw th;
        }
    }

    private HttpClient getHttpClient() {
        BasicHttpParams basicHttpParams = new BasicHttpParams();
        basicHttpParams.setParameter("http.protocol.cookie-policy", "rfc2109");
        HttpConnectionParams.setConnectionTimeout(basicHttpParams, this.connectionTimeOut);
        HttpConnectionParams.setSoTimeout(basicHttpParams, this.socketTimeOut);
        HttpConnectionParams.setSocketBufferSize(basicHttpParams, 8192);
        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(new Scheme("http", new PlainSocketFactory(), 80));
        if (ACRA.getConfig().disableSSLCertValidation()) {
            schemeRegistry.register(new Scheme("https", new FakeSocketFactory(), 443));
        } else {
            schemeRegistry.register(new Scheme("https", SSLSocketFactory.getSocketFactory(), 443));
        }
        DefaultHttpClient defaultHttpClient = new DefaultHttpClient(new ThreadSafeClientConnManager(basicHttpParams, schemeRegistry), basicHttpParams);
        defaultHttpClient.setHttpRequestRetryHandler(new SocketTimeOutRetryHandler(basicHttpParams, this.maxNrRetries, null));
        return defaultHttpClient;
    }

    private UsernamePasswordCredentials getCredentials() {
        if (this.login == null && this.password == null) {
            return null;
        }
        return new UsernamePasswordCredentials(this.login, this.password);
    }

    private HttpEntityEnclosingRequestBase getHttpRequest(URL url, Method method, String str, Type type) throws UnsupportedEncodingException, UnsupportedOperationException {
        HttpPut httpPut;
        int i = AnonymousClass1.$SwitchMap$org$acra$sender$HttpSender$Method[method.ordinal()];
        if (i == 1) {
            httpPut = new HttpPost(url.toString());
        } else if (i == 2) {
            httpPut = new HttpPut(url.toString());
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("Unknown method: ");
            sb.append(method.name());
            throw new UnsupportedOperationException(sb.toString());
        }
        UsernamePasswordCredentials credentials = getCredentials();
        if (credentials != null) {
            httpPut.addHeader(BasicScheme.authenticate(credentials, "UTF-8", false));
        }
        httpPut.setHeader("User-Agent", "Android");
        httpPut.setHeader("Accept", "text/html,application/xml,application/json,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5");
        httpPut.setHeader("Content-Type", type.getContentType());
        Map<String, String> map = this.headers;
        if (map != null) {
            for (String next : map.keySet()) {
                httpPut.setHeader(next, this.headers.get(next));
            }
        }
        httpPut.setEntity(new StringEntity(str, "UTF-8"));
        return httpPut;
    }

    public static String getParamsAsFormString(Map<?, ?> map) throws UnsupportedEncodingException {
        StringBuilder sb = new StringBuilder();
        for (Object next : map.keySet()) {
            if (sb.length() != 0) {
                sb.append('&');
            }
            Object obj = map.get(next);
            if (obj == null) {
                obj = "";
            }
            sb.append(URLEncoder.encode(next.toString(), "UTF-8"));
            sb.append('=');
            sb.append(URLEncoder.encode(obj.toString(), "UTF-8"));
        }
        return sb.toString();
    }
}