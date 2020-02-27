package com.squareup.okhttp.internal.http;

import io.fabric.sdk.android.services.network.HttpRequest;

public final class HttpMethod {
    public static boolean invalidatesCache(String method) {
        return method.equals(HttpRequest.METHOD_POST) || method.equals("PATCH") || method.equals(HttpRequest.METHOD_PUT) || method.equals(HttpRequest.METHOD_DELETE);
    }

    public static boolean requiresRequestBody(String method) {
        return method.equals(HttpRequest.METHOD_POST) || method.equals(HttpRequest.METHOD_PUT) || method.equals("PATCH");
    }

    public static boolean permitsRequestBody(String method) {
        return requiresRequestBody(method) || method.equals(HttpRequest.METHOD_DELETE);
    }

    private HttpMethod() {
    }
}