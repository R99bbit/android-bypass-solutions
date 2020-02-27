package com.squareup.okhttp.internal.http;

import com.squareup.okhttp.Protocol;
import com.squareup.okhttp.Request;
import java.net.Proxy.Type;
import java.net.URL;

public final class RequestLine {
    private RequestLine() {
    }

    static String get(Request request, Type proxyType, Protocol protocol) {
        StringBuilder result = new StringBuilder();
        result.append(request.method());
        result.append(' ');
        if (includeAuthorityInRequestLine(request, proxyType)) {
            result.append(request.url());
        } else {
            result.append(requestPath(request.url()));
        }
        result.append(' ');
        result.append(version(protocol));
        return result.toString();
    }

    private static boolean includeAuthorityInRequestLine(Request request, Type proxyType) {
        return !request.isHttps() && proxyType == Type.HTTP;
    }

    public static String requestPath(URL url) {
        String pathAndQuery = url.getFile();
        if (pathAndQuery == null) {
            return "/";
        }
        if (!pathAndQuery.startsWith("/")) {
            return "/" + pathAndQuery;
        }
        return pathAndQuery;
    }

    public static String version(Protocol protocol) {
        return protocol == Protocol.HTTP_1_0 ? "HTTP/1.0" : "HTTP/1.1";
    }
}