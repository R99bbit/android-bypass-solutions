package okhttp3.internal.http;

import io.fabric.sdk.android.services.network.HttpRequest;

public final class HttpMethod {
    public static boolean invalidatesCache(String method) {
        return method.equals(HttpRequest.METHOD_POST) || method.equals("PATCH") || method.equals(HttpRequest.METHOD_PUT) || method.equals(HttpRequest.METHOD_DELETE) || method.equals("MOVE");
    }

    public static boolean requiresRequestBody(String method) {
        return method.equals(HttpRequest.METHOD_POST) || method.equals(HttpRequest.METHOD_PUT) || method.equals("PATCH") || method.equals("PROPPATCH") || method.equals("REPORT");
    }

    public static boolean permitsRequestBody(String method) {
        return !method.equals(HttpRequest.METHOD_GET) && !method.equals(HttpRequest.METHOD_HEAD);
    }

    public static boolean redirectsWithBody(String method) {
        return method.equals("PROPFIND");
    }

    public static boolean redirectsToGet(String method) {
        return !method.equals("PROPFIND");
    }

    private HttpMethod() {
    }
}