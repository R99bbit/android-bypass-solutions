package okhttp3.internal.huc;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ProtocolException;
import java.net.URL;
import java.security.Permission;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.Map;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import okhttp3.Handshake;
import okhttp3.OkHttpClient;
import okhttp3.internal.URLFilter;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;

public final class OkHttpsURLConnection extends DelegatingHttpsURLConnection {
    private final OkHttpURLConnection delegate;

    public /* bridge */ /* synthetic */ void addRequestProperty(String str, String str2) {
        super.addRequestProperty(str, str2);
    }

    public /* bridge */ /* synthetic */ void connect() throws IOException {
        super.connect();
    }

    public /* bridge */ /* synthetic */ void disconnect() {
        super.disconnect();
    }

    public /* bridge */ /* synthetic */ boolean getAllowUserInteraction() {
        return super.getAllowUserInteraction();
    }

    public /* bridge */ /* synthetic */ String getCipherSuite() {
        return super.getCipherSuite();
    }

    public /* bridge */ /* synthetic */ int getConnectTimeout() {
        return super.getConnectTimeout();
    }

    public /* bridge */ /* synthetic */ Object getContent() throws IOException {
        return super.getContent();
    }

    public /* bridge */ /* synthetic */ Object getContent(Class[] clsArr) throws IOException {
        return super.getContent(clsArr);
    }

    public /* bridge */ /* synthetic */ String getContentEncoding() {
        return super.getContentEncoding();
    }

    public /* bridge */ /* synthetic */ int getContentLength() {
        return super.getContentLength();
    }

    @IgnoreJRERequirement
    public /* bridge */ /* synthetic */ long getContentLengthLong() {
        return super.getContentLengthLong();
    }

    public /* bridge */ /* synthetic */ String getContentType() {
        return super.getContentType();
    }

    public /* bridge */ /* synthetic */ long getDate() {
        return super.getDate();
    }

    public /* bridge */ /* synthetic */ boolean getDefaultUseCaches() {
        return super.getDefaultUseCaches();
    }

    public /* bridge */ /* synthetic */ boolean getDoInput() {
        return super.getDoInput();
    }

    public /* bridge */ /* synthetic */ boolean getDoOutput() {
        return super.getDoOutput();
    }

    public /* bridge */ /* synthetic */ InputStream getErrorStream() {
        return super.getErrorStream();
    }

    public /* bridge */ /* synthetic */ long getExpiration() {
        return super.getExpiration();
    }

    public /* bridge */ /* synthetic */ String getHeaderField(int i) {
        return super.getHeaderField(i);
    }

    public /* bridge */ /* synthetic */ String getHeaderField(String str) {
        return super.getHeaderField(str);
    }

    public /* bridge */ /* synthetic */ long getHeaderFieldDate(String str, long j) {
        return super.getHeaderFieldDate(str, j);
    }

    public /* bridge */ /* synthetic */ int getHeaderFieldInt(String str, int i) {
        return super.getHeaderFieldInt(str, i);
    }

    public /* bridge */ /* synthetic */ String getHeaderFieldKey(int i) {
        return super.getHeaderFieldKey(i);
    }

    @IgnoreJRERequirement
    public /* bridge */ /* synthetic */ long getHeaderFieldLong(String str, long j) {
        return super.getHeaderFieldLong(str, j);
    }

    public /* bridge */ /* synthetic */ Map getHeaderFields() {
        return super.getHeaderFields();
    }

    public /* bridge */ /* synthetic */ long getIfModifiedSince() {
        return super.getIfModifiedSince();
    }

    public /* bridge */ /* synthetic */ InputStream getInputStream() throws IOException {
        return super.getInputStream();
    }

    public /* bridge */ /* synthetic */ boolean getInstanceFollowRedirects() {
        return super.getInstanceFollowRedirects();
    }

    public /* bridge */ /* synthetic */ long getLastModified() {
        return super.getLastModified();
    }

    public /* bridge */ /* synthetic */ Certificate[] getLocalCertificates() {
        return super.getLocalCertificates();
    }

    public /* bridge */ /* synthetic */ Principal getLocalPrincipal() {
        return super.getLocalPrincipal();
    }

    public /* bridge */ /* synthetic */ OutputStream getOutputStream() throws IOException {
        return super.getOutputStream();
    }

    public /* bridge */ /* synthetic */ Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return super.getPeerPrincipal();
    }

    public /* bridge */ /* synthetic */ Permission getPermission() throws IOException {
        return super.getPermission();
    }

    public /* bridge */ /* synthetic */ int getReadTimeout() {
        return super.getReadTimeout();
    }

    public /* bridge */ /* synthetic */ String getRequestMethod() {
        return super.getRequestMethod();
    }

    public /* bridge */ /* synthetic */ Map getRequestProperties() {
        return super.getRequestProperties();
    }

    public /* bridge */ /* synthetic */ String getRequestProperty(String str) {
        return super.getRequestProperty(str);
    }

    public /* bridge */ /* synthetic */ int getResponseCode() throws IOException {
        return super.getResponseCode();
    }

    public /* bridge */ /* synthetic */ String getResponseMessage() throws IOException {
        return super.getResponseMessage();
    }

    public /* bridge */ /* synthetic */ Certificate[] getServerCertificates() throws SSLPeerUnverifiedException {
        return super.getServerCertificates();
    }

    public /* bridge */ /* synthetic */ URL getURL() {
        return super.getURL();
    }

    public /* bridge */ /* synthetic */ boolean getUseCaches() {
        return super.getUseCaches();
    }

    public /* bridge */ /* synthetic */ void setAllowUserInteraction(boolean z) {
        super.setAllowUserInteraction(z);
    }

    public /* bridge */ /* synthetic */ void setChunkedStreamingMode(int i) {
        super.setChunkedStreamingMode(i);
    }

    public /* bridge */ /* synthetic */ void setConnectTimeout(int i) {
        super.setConnectTimeout(i);
    }

    public /* bridge */ /* synthetic */ void setDefaultUseCaches(boolean z) {
        super.setDefaultUseCaches(z);
    }

    public /* bridge */ /* synthetic */ void setDoInput(boolean z) {
        super.setDoInput(z);
    }

    public /* bridge */ /* synthetic */ void setDoOutput(boolean z) {
        super.setDoOutput(z);
    }

    public /* bridge */ /* synthetic */ void setFixedLengthStreamingMode(int i) {
        super.setFixedLengthStreamingMode(i);
    }

    @IgnoreJRERequirement
    public /* bridge */ /* synthetic */ void setFixedLengthStreamingMode(long j) {
        super.setFixedLengthStreamingMode(j);
    }

    public /* bridge */ /* synthetic */ void setIfModifiedSince(long j) {
        super.setIfModifiedSince(j);
    }

    public /* bridge */ /* synthetic */ void setInstanceFollowRedirects(boolean z) {
        super.setInstanceFollowRedirects(z);
    }

    public /* bridge */ /* synthetic */ void setReadTimeout(int i) {
        super.setReadTimeout(i);
    }

    public /* bridge */ /* synthetic */ void setRequestMethod(String str) throws ProtocolException {
        super.setRequestMethod(str);
    }

    public /* bridge */ /* synthetic */ void setRequestProperty(String str, String str2) {
        super.setRequestProperty(str, str2);
    }

    public /* bridge */ /* synthetic */ void setUseCaches(boolean z) {
        super.setUseCaches(z);
    }

    public /* bridge */ /* synthetic */ String toString() {
        return super.toString();
    }

    public /* bridge */ /* synthetic */ boolean usingProxy() {
        return super.usingProxy();
    }

    public OkHttpsURLConnection(URL url, OkHttpClient okHttpClient) {
        this(new OkHttpURLConnection(url, okHttpClient));
    }

    public OkHttpsURLConnection(URL url, OkHttpClient okHttpClient, URLFilter uRLFilter) {
        this(new OkHttpURLConnection(url, okHttpClient, uRLFilter));
    }

    public OkHttpsURLConnection(OkHttpURLConnection okHttpURLConnection) {
        super(okHttpURLConnection);
        this.delegate = okHttpURLConnection;
    }

    /* access modifiers changed from: protected */
    public Handshake handshake() {
        if (this.delegate.call != null) {
            return this.delegate.handshake;
        }
        throw new IllegalStateException("Connection has not yet been established");
    }

    public void setHostnameVerifier(HostnameVerifier hostnameVerifier) {
        OkHttpURLConnection okHttpURLConnection = this.delegate;
        okHttpURLConnection.client = okHttpURLConnection.client.newBuilder().hostnameVerifier(hostnameVerifier).build();
    }

    public HostnameVerifier getHostnameVerifier() {
        return this.delegate.client.hostnameVerifier();
    }

    public void setSSLSocketFactory(SSLSocketFactory sSLSocketFactory) {
        OkHttpURLConnection okHttpURLConnection = this.delegate;
        okHttpURLConnection.client = okHttpURLConnection.client.newBuilder().sslSocketFactory(sSLSocketFactory).build();
    }

    public SSLSocketFactory getSSLSocketFactory() {
        return this.delegate.client.sslSocketFactory();
    }
}