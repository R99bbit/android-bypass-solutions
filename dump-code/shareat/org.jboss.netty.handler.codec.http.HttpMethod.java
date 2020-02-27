package org.jboss.netty.handler.codec.http;

import io.fabric.sdk.android.services.network.HttpRequest;
import java.util.HashMap;
import java.util.Map;

public class HttpMethod implements Comparable<HttpMethod> {
    public static final HttpMethod CONNECT = new HttpMethod("CONNECT");
    public static final HttpMethod DELETE = new HttpMethod(HttpRequest.METHOD_DELETE);
    public static final HttpMethod GET = new HttpMethod(HttpRequest.METHOD_GET);
    public static final HttpMethod HEAD = new HttpMethod(HttpRequest.METHOD_HEAD);
    public static final HttpMethod OPTIONS = new HttpMethod(HttpRequest.METHOD_OPTIONS);
    public static final HttpMethod PATCH = new HttpMethod("PATCH");
    public static final HttpMethod POST = new HttpMethod(HttpRequest.METHOD_POST);
    public static final HttpMethod PUT = new HttpMethod(HttpRequest.METHOD_PUT);
    public static final HttpMethod TRACE = new HttpMethod(HttpRequest.METHOD_TRACE);
    private static final Map<String, HttpMethod> methodMap = new HashMap();
    private final String name;

    static {
        methodMap.put(OPTIONS.toString(), OPTIONS);
        methodMap.put(GET.toString(), GET);
        methodMap.put(HEAD.toString(), HEAD);
        methodMap.put(POST.toString(), POST);
        methodMap.put(PUT.toString(), PUT);
        methodMap.put(PATCH.toString(), PATCH);
        methodMap.put(DELETE.toString(), DELETE);
        methodMap.put(TRACE.toString(), TRACE);
        methodMap.put(CONNECT.toString(), CONNECT);
    }

    public static HttpMethod valueOf(String name2) {
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        String name3 = name2.trim();
        if (name3.length() == 0) {
            throw new IllegalArgumentException("empty name");
        }
        HttpMethod result = methodMap.get(name3);
        return result != null ? result : new HttpMethod(name3);
    }

    public HttpMethod(String name2) {
        if (name2 == null) {
            throw new NullPointerException("name");
        }
        String name3 = name2.trim();
        if (name3.length() == 0) {
            throw new IllegalArgumentException("empty name");
        }
        for (int i = 0; i < name3.length(); i++) {
            if (Character.isISOControl(name3.charAt(i)) || Character.isWhitespace(name3.charAt(i))) {
                throw new IllegalArgumentException("invalid character in name");
            }
        }
        this.name = name3;
    }

    public String getName() {
        return this.name;
    }

    public int hashCode() {
        return getName().hashCode();
    }

    public boolean equals(Object o) {
        if (!(o instanceof HttpMethod)) {
            return false;
        }
        return getName().equals(((HttpMethod) o).getName());
    }

    public String toString() {
        return getName();
    }

    public int compareTo(HttpMethod o) {
        return getName().compareTo(o.getName());
    }
}