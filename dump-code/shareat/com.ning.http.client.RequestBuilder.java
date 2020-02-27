package com.ning.http.client;

import com.ning.http.client.Request.EntityWriter;
import com.ning.http.client.cookie.Cookie;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.InputStream;
import java.util.Collection;
import java.util.Map;

public class RequestBuilder extends RequestBuilderBase<RequestBuilder> {
    public RequestBuilder() {
        super(RequestBuilder.class, HttpRequest.METHOD_GET, false);
    }

    public RequestBuilder(String method) {
        super(RequestBuilder.class, method, false);
    }

    public RequestBuilder(String method, boolean useRawUrl) {
        super(RequestBuilder.class, method, useRawUrl);
    }

    public RequestBuilder(Request prototype) {
        super(RequestBuilder.class, prototype);
    }

    public RequestBuilder addBodyPart(Part part) throws IllegalArgumentException {
        return (RequestBuilder) super.addBodyPart(part);
    }

    public RequestBuilder addCookie(Cookie cookie) {
        return (RequestBuilder) super.addCookie(cookie);
    }

    public RequestBuilder addHeader(String name, String value) {
        return (RequestBuilder) super.addHeader(name, value);
    }

    public RequestBuilder addParameter(String key, String value) throws IllegalArgumentException {
        return (RequestBuilder) super.addParameter(key, value);
    }

    public RequestBuilder addQueryParameter(String name, String value) {
        return (RequestBuilder) super.addQueryParameter(name, value);
    }

    public RequestBuilder setQueryParameters(FluentStringsMap parameters) {
        return (RequestBuilder) super.setQueryParameters(parameters);
    }

    public Request build() {
        return super.build();
    }

    public RequestBuilder setBody(byte[] data) throws IllegalArgumentException {
        return (RequestBuilder) super.setBody(data);
    }

    public RequestBuilder setBody(EntityWriter dataWriter, long length) throws IllegalArgumentException {
        return (RequestBuilder) super.setBody(dataWriter, length);
    }

    public RequestBuilder setBody(EntityWriter dataWriter) {
        return (RequestBuilder) super.setBody(dataWriter);
    }

    @Deprecated
    public RequestBuilder setBody(InputStream stream) throws IllegalArgumentException {
        return (RequestBuilder) super.setBody(stream);
    }

    public RequestBuilder setBody(String data) throws IllegalArgumentException {
        return (RequestBuilder) super.setBody(data);
    }

    public RequestBuilder setHeader(String name, String value) {
        return (RequestBuilder) super.setHeader(name, value);
    }

    public RequestBuilder setHeaders(FluentCaseInsensitiveStringsMap headers) {
        return (RequestBuilder) super.setHeaders(headers);
    }

    public RequestBuilder setHeaders(Map<String, Collection<String>> headers) {
        return (RequestBuilder) super.setHeaders(headers);
    }

    public RequestBuilder setParameters(Map<String, Collection<String>> parameters) throws IllegalArgumentException {
        return (RequestBuilder) super.setParameters(parameters);
    }

    public RequestBuilder setParameters(FluentStringsMap parameters) throws IllegalArgumentException {
        return (RequestBuilder) super.setParameters(parameters);
    }

    public RequestBuilder setMethod(String method) {
        return (RequestBuilder) super.setMethod(method);
    }

    public RequestBuilder setUrl(String url) {
        return (RequestBuilder) super.setUrl(url);
    }

    public RequestBuilder setProxyServer(ProxyServer proxyServer) {
        return (RequestBuilder) super.setProxyServer(proxyServer);
    }

    public RequestBuilder setVirtualHost(String virtualHost) {
        return (RequestBuilder) super.setVirtualHost(virtualHost);
    }

    public RequestBuilder setFollowRedirects(boolean followRedirects) {
        return (RequestBuilder) super.setFollowRedirects(followRedirects);
    }

    public RequestBuilder addOrReplaceCookie(Cookie c) {
        return (RequestBuilder) super.addOrReplaceCookie(c);
    }
}