package org.jboss.netty.handler.codec.rtsp;

import org.jboss.netty.handler.codec.http.HttpVersion;

public final class RtspVersions {
    public static final HttpVersion RTSP_1_0 = new HttpVersion("RTSP", 1, 0, true);

    public static HttpVersion valueOf(String text) {
        if (text == null) {
            throw new NullPointerException("text");
        }
        String text2 = text.trim().toUpperCase();
        if ("RTSP/1.0".equals(text2)) {
            return RTSP_1_0;
        }
        return new HttpVersion(text2, true);
    }

    private RtspVersions() {
    }
}