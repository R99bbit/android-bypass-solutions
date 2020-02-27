package org.jboss.netty.handler.codec.http;

import java.io.UnsupportedEncodingException;
import java.util.Iterator;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpHeaders.Values;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;
import org.jboss.netty.util.CharsetUtil;

public abstract class HttpMessageEncoder extends OneToOneEncoder {
    private static final byte[] CRLF = {HttpConstants.CR, 10};
    private static final ChannelBuffer LAST_CHUNK = ChannelBuffers.copiedBuffer((CharSequence) "0\r\n\r\n", CharsetUtil.US_ASCII);
    private volatile boolean transferEncodingChunked;

    /* access modifiers changed from: protected */
    public abstract void encodeInitialLine(ChannelBuffer channelBuffer, HttpMessage httpMessage) throws Exception;

    protected HttpMessageEncoder() {
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        boolean contentMustBeEmpty;
        if (msg instanceof HttpMessage) {
            HttpMessage m = (HttpMessage) msg;
            if (!m.isChunked()) {
                contentMustBeEmpty = HttpCodecUtil.isTransferEncodingChunked(m);
                this.transferEncodingChunked = contentMustBeEmpty;
            } else if (HttpCodecUtil.isContentLengthSet(m)) {
                contentMustBeEmpty = false;
                this.transferEncodingChunked = false;
                HttpCodecUtil.removeTransferEncodingChunked(m);
            } else {
                if (!HttpCodecUtil.isTransferEncodingChunked(m)) {
                    m.headers().add((String) Names.TRANSFER_ENCODING, (Object) Values.CHUNKED);
                }
                contentMustBeEmpty = true;
                this.transferEncodingChunked = true;
            }
            ChannelBuffer header = ChannelBuffers.dynamicBuffer(channel.getConfig().getBufferFactory());
            encodeInitialLine(header, m);
            encodeHeaders(header, m);
            header.writeByte(13);
            header.writeByte(10);
            ChannelBuffer content = m.getContent();
            if (!content.readable()) {
                return header;
            }
            if (contentMustBeEmpty) {
                throw new IllegalArgumentException("HttpMessage.content must be empty if Transfer-Encoding is chunked.");
            }
            return ChannelBuffers.wrappedBuffer(header, content);
        } else if (!(msg instanceof HttpChunk)) {
            return msg;
        } else {
            HttpChunk chunk = (HttpChunk) msg;
            if (!this.transferEncodingChunked) {
                return chunk.getContent();
            }
            if (chunk.isLast()) {
                this.transferEncodingChunked = false;
                if (!(chunk instanceof HttpChunkTrailer)) {
                    return LAST_CHUNK.duplicate();
                }
                ChannelBuffer trailer = ChannelBuffers.dynamicBuffer(channel.getConfig().getBufferFactory());
                trailer.writeByte(48);
                trailer.writeByte(13);
                trailer.writeByte(10);
                encodeTrailingHeaders(trailer, (HttpChunkTrailer) chunk);
                trailer.writeByte(13);
                trailer.writeByte(10);
                return trailer;
            }
            ChannelBuffer content2 = chunk.getContent();
            int contentLength = content2.readableBytes();
            return ChannelBuffers.wrappedBuffer(ChannelBuffers.copiedBuffer((CharSequence) Integer.toHexString(contentLength), CharsetUtil.US_ASCII), ChannelBuffers.wrappedBuffer(CRLF), content2.slice(content2.readerIndex(), contentLength), ChannelBuffers.wrappedBuffer(CRLF));
        }
    }

    private static void encodeHeaders(ChannelBuffer buf, HttpMessage message) {
        try {
            Iterator i$ = message.headers().iterator();
            while (i$.hasNext()) {
                Entry<String, String> h = (Entry) i$.next();
                encodeHeader(buf, h.getKey(), h.getValue());
            }
        } catch (UnsupportedEncodingException e) {
            throw ((Error) new Error().initCause(e));
        }
    }

    private static void encodeTrailingHeaders(ChannelBuffer buf, HttpChunkTrailer trailer) {
        try {
            Iterator i$ = trailer.trailingHeaders().iterator();
            while (i$.hasNext()) {
                Entry<String, String> h = (Entry) i$.next();
                encodeHeader(buf, h.getKey(), h.getValue());
            }
        } catch (UnsupportedEncodingException e) {
            throw ((Error) new Error().initCause(e));
        }
    }

    private static void encodeHeader(ChannelBuffer buf, String header, String value) throws UnsupportedEncodingException {
        encodeAscii(header, buf);
        buf.writeByte(58);
        buf.writeByte(32);
        encodeAscii(value, buf);
        buf.writeByte(13);
        buf.writeByte(10);
    }

    protected static void encodeAscii(String s, ChannelBuffer buf) {
        for (int i = 0; i < s.length(); i++) {
            buf.writeByte(s.charAt(i));
        }
    }
}