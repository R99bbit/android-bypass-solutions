package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.compression.ZlibDecoder;
import org.jboss.netty.handler.codec.compression.ZlibWrapper;
import org.jboss.netty.handler.codec.embedder.DecoderEmbedder;

public class HttpContentDecompressor extends HttpContentDecoder {
    /* access modifiers changed from: protected */
    public DecoderEmbedder<ChannelBuffer> newContentDecoder(String contentEncoding) throws Exception {
        if ("gzip".equalsIgnoreCase(contentEncoding) || "x-gzip".equalsIgnoreCase(contentEncoding)) {
            return new DecoderEmbedder<>(new ZlibDecoder(ZlibWrapper.GZIP));
        } else if (!"deflate".equalsIgnoreCase(contentEncoding) && !"x-deflate".equalsIgnoreCase(contentEncoding)) {
            return null;
        } else {
            return new DecoderEmbedder<>(new ZlibDecoder(ZlibWrapper.ZLIB_OR_NONE));
        }
    }
}