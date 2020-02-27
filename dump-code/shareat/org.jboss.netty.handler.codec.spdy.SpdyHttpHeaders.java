package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMessage;

public final class SpdyHttpHeaders {

    public static final class Names {
        public static final String ASSOCIATED_TO_STREAM_ID = "X-SPDY-Associated-To-Stream-ID";
        public static final String PRIORITY = "X-SPDY-Priority";
        public static final String SCHEME = "X-SPDY-Scheme";
        public static final String STREAM_ID = "X-SPDY-Stream-ID";
        public static final String URL = "X-SPDY-URL";

        private Names() {
        }
    }

    private SpdyHttpHeaders() {
    }

    public static void removeStreamId(HttpMessage message) {
        message.headers().remove(Names.STREAM_ID);
    }

    public static int getStreamId(HttpMessage message) {
        return HttpHeaders.getIntHeader(message, Names.STREAM_ID);
    }

    public static void setStreamId(HttpMessage message, int streamId) {
        HttpHeaders.setIntHeader(message, (String) Names.STREAM_ID, streamId);
    }

    public static void removeAssociatedToStreamId(HttpMessage message) {
        message.headers().remove(Names.ASSOCIATED_TO_STREAM_ID);
    }

    public static int getAssociatedToStreamId(HttpMessage message) {
        return HttpHeaders.getIntHeader(message, Names.ASSOCIATED_TO_STREAM_ID, 0);
    }

    public static void setAssociatedToStreamId(HttpMessage message, int associatedToStreamId) {
        HttpHeaders.setIntHeader(message, (String) Names.ASSOCIATED_TO_STREAM_ID, associatedToStreamId);
    }

    public static void removePriority(HttpMessage message) {
        message.headers().remove(Names.PRIORITY);
    }

    public static byte getPriority(HttpMessage message) {
        return (byte) HttpHeaders.getIntHeader(message, Names.PRIORITY, 0);
    }

    public static void setPriority(HttpMessage message, byte priority) {
        HttpHeaders.setIntHeader(message, (String) Names.PRIORITY, (int) priority);
    }

    public static void removeUrl(HttpMessage message) {
        message.headers().remove(Names.URL);
    }

    public static String getUrl(HttpMessage message) {
        return message.headers().get(Names.URL);
    }

    public static void setUrl(HttpMessage message, String url) {
        message.headers().set((String) Names.URL, (Object) url);
    }

    public static void removeScheme(HttpMessage message) {
        message.headers().remove(Names.SCHEME);
    }

    public static String getScheme(HttpMessage message) {
        return message.headers().get(Names.SCHEME);
    }

    public static void setScheme(HttpMessage message, String scheme) {
        message.headers().set((String) Names.SCHEME, (Object) scheme);
    }
}