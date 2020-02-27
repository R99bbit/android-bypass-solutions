package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.compression.JdkZlibEncoder;
import org.jboss.netty.handler.codec.compression.ZlibEncoder;
import org.jboss.netty.handler.codec.compression.ZlibWrapper;
import org.jboss.netty.handler.codec.embedder.EncoderEmbedder;
import org.jboss.netty.util.internal.DetectionUtil;
import org.jboss.netty.util.internal.StringUtil;

public class HttpContentCompressor extends HttpContentEncoder {
    private final int compressionLevel;
    private final int memLevel;
    private final int windowBits;

    public HttpContentCompressor() {
        this(6);
    }

    public HttpContentCompressor(int compressionLevel2) {
        this(compressionLevel2, 15, 8);
    }

    public HttpContentCompressor(int compressionLevel2, int windowBits2, int memLevel2) {
        if (compressionLevel2 < 0 || compressionLevel2 > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel2 + " (expected: 0-9)");
        } else if (windowBits2 < 9 || windowBits2 > 15) {
            throw new IllegalArgumentException("windowBits: " + windowBits2 + " (expected: 9-15)");
        } else if (memLevel2 < 1 || memLevel2 > 9) {
            throw new IllegalArgumentException("memLevel: " + memLevel2 + " (expected: 1-9)");
        } else {
            this.compressionLevel = compressionLevel2;
            this.windowBits = windowBits2;
            this.memLevel = memLevel2;
        }
    }

    /* access modifiers changed from: protected */
    public EncoderEmbedder<ChannelBuffer> newContentEncoder(HttpMessage msg, String acceptEncoding) throws Exception {
        String contentEncoding = msg.headers().get("Content-Encoding");
        if (contentEncoding != null && !"identity".equalsIgnoreCase(contentEncoding)) {
            return null;
        }
        ZlibWrapper wrapper = determineWrapper(acceptEncoding);
        if (wrapper == null) {
            return null;
        }
        if (DetectionUtil.javaVersion() >= 7) {
            return new EncoderEmbedder<>(new JdkZlibEncoder(wrapper, this.compressionLevel));
        }
        return new EncoderEmbedder<>(new ZlibEncoder(wrapper, this.compressionLevel, this.windowBits, this.memLevel));
    }

    /* access modifiers changed from: protected */
    public String getTargetContentEncoding(String acceptEncoding) throws Exception {
        ZlibWrapper wrapper = determineWrapper(acceptEncoding);
        if (wrapper == null) {
            return null;
        }
        switch (wrapper) {
            case GZIP:
                return "gzip";
            case ZLIB:
                return "deflate";
            default:
                throw new Error();
        }
    }

    private static ZlibWrapper determineWrapper(String acceptEncoding) {
        String[] arr$;
        float starQ = -1.0f;
        float gzipQ = -1.0f;
        float deflateQ = -1.0f;
        for (String encoding : StringUtil.split(acceptEncoding, ',')) {
            float q = 1.0f;
            int equalsPos = encoding.indexOf(61);
            if (equalsPos != -1) {
                try {
                    q = Float.valueOf(encoding.substring(equalsPos + 1)).floatValue();
                } catch (NumberFormatException e) {
                    q = 0.0f;
                }
            }
            if (encoding.indexOf(42) >= 0) {
                starQ = q;
            } else if (encoding.contains("gzip") && q > gzipQ) {
                gzipQ = q;
            } else if (encoding.contains("deflate") && q > deflateQ) {
                deflateQ = q;
            }
        }
        if (gzipQ <= 0.0f && deflateQ <= 0.0f) {
            if (starQ > 0.0f) {
                if (gzipQ == -1.0f) {
                    return ZlibWrapper.GZIP;
                }
                if (deflateQ == -1.0f) {
                    return ZlibWrapper.ZLIB;
                }
            }
            return null;
        } else if (gzipQ >= deflateQ) {
            return ZlibWrapper.GZIP;
        } else {
            return ZlibWrapper.ZLIB;
        }
    }
}