package org.jboss.netty.handler.codec.spdy;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.DefaultHttpResponse;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpHeaders.Names;
import org.jboss.netty.handler.codec.http.HttpMessage;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;

public class SpdyHttpDecoder extends OneToOneDecoder {
    private final int maxContentLength;
    private final Map<Integer, HttpMessage> messageMap;
    private final int spdyVersion;

    public SpdyHttpDecoder(SpdyVersion spdyVersion2, int maxContentLength2) {
        this(spdyVersion2, maxContentLength2, new HashMap());
    }

    protected SpdyHttpDecoder(SpdyVersion spdyVersion2, int maxContentLength2, Map<Integer, HttpMessage> messageMap2) {
        if (spdyVersion2 == null) {
            throw new NullPointerException("spdyVersion");
        } else if (maxContentLength2 <= 0) {
            throw new IllegalArgumentException("maxContentLength must be a positive integer: " + maxContentLength2);
        } else {
            this.spdyVersion = spdyVersion2.getVersion();
            this.maxContentLength = maxContentLength2;
            this.messageMap = messageMap2;
        }
    }

    /* access modifiers changed from: protected */
    public HttpMessage putMessage(int streamId, HttpMessage message) {
        return this.messageMap.put(Integer.valueOf(streamId), message);
    }

    /* access modifiers changed from: protected */
    public HttpMessage getMessage(int streamId) {
        return this.messageMap.get(Integer.valueOf(streamId));
    }

    /* access modifiers changed from: protected */
    public HttpMessage removeMessage(int streamId) {
        return this.messageMap.remove(Integer.valueOf(streamId));
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (msg instanceof SpdySynStreamFrame) {
            SpdySynStreamFrame spdySynStreamFrame = (SpdySynStreamFrame) msg;
            int streamId = spdySynStreamFrame.getStreamId();
            if (SpdyCodecUtil.isServerId(streamId)) {
                int associatedToStreamId = spdySynStreamFrame.getAssociatedToStreamId();
                if (associatedToStreamId == 0) {
                    Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId, SpdyStreamStatus.INVALID_STREAM));
                }
                String URL = SpdyHeaders.getUrl(this.spdyVersion, spdySynStreamFrame);
                if (URL == null) {
                    Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId, SpdyStreamStatus.PROTOCOL_ERROR));
                }
                if (spdySynStreamFrame.isTruncated()) {
                    Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId, SpdyStreamStatus.INTERNAL_ERROR));
                }
                try {
                    HttpResponse httpResponse = createHttpResponse(this.spdyVersion, spdySynStreamFrame);
                    SpdyHttpHeaders.setStreamId(httpResponse, streamId);
                    SpdyHttpHeaders.setAssociatedToStreamId(httpResponse, associatedToStreamId);
                    SpdyHttpHeaders.setPriority(httpResponse, spdySynStreamFrame.getPriority());
                    SpdyHttpHeaders.setUrl(httpResponse, URL);
                    if (spdySynStreamFrame.isLast()) {
                        HttpHeaders.setContentLength(httpResponse, 0);
                        return httpResponse;
                    }
                    putMessage(streamId, httpResponse);
                } catch (Exception e) {
                    Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId, SpdyStreamStatus.PROTOCOL_ERROR));
                }
            } else {
                if (spdySynStreamFrame.isTruncated()) {
                    DefaultSpdySynReplyFrame defaultSpdySynReplyFrame = new DefaultSpdySynReplyFrame(streamId);
                    defaultSpdySynReplyFrame.setLast(true);
                    SpdyHeaders.setStatus(this.spdyVersion, defaultSpdySynReplyFrame, HttpResponseStatus.REQUEST_HEADER_FIELDS_TOO_LARGE);
                    SpdyHeaders.setVersion(this.spdyVersion, defaultSpdySynReplyFrame, HttpVersion.HTTP_1_0);
                    Channels.write(ctx, Channels.future(channel), (Object) defaultSpdySynReplyFrame);
                }
                try {
                    HttpRequest httpRequest = createHttpRequest(this.spdyVersion, spdySynStreamFrame);
                    SpdyHttpHeaders.setStreamId(httpRequest, streamId);
                    if (spdySynStreamFrame.isLast()) {
                        return httpRequest;
                    }
                    putMessage(streamId, httpRequest);
                } catch (Exception e2) {
                    DefaultSpdySynReplyFrame defaultSpdySynReplyFrame2 = new DefaultSpdySynReplyFrame(streamId);
                    defaultSpdySynReplyFrame2.setLast(true);
                    SpdyHeaders.setStatus(this.spdyVersion, defaultSpdySynReplyFrame2, HttpResponseStatus.BAD_REQUEST);
                    SpdyHeaders.setVersion(this.spdyVersion, defaultSpdySynReplyFrame2, HttpVersion.HTTP_1_0);
                    Channels.write(ctx, Channels.future(channel), (Object) defaultSpdySynReplyFrame2);
                }
            }
        } else if (msg instanceof SpdySynReplyFrame) {
            SpdySynReplyFrame spdySynReplyFrame = (SpdySynReplyFrame) msg;
            int streamId2 = spdySynReplyFrame.getStreamId();
            if (spdySynReplyFrame.isTruncated()) {
                Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId2, SpdyStreamStatus.INTERNAL_ERROR));
            }
            try {
                HttpResponse httpResponse2 = createHttpResponse(this.spdyVersion, spdySynReplyFrame);
                SpdyHttpHeaders.setStreamId(httpResponse2, streamId2);
                if (spdySynReplyFrame.isLast()) {
                    HttpHeaders.setContentLength(httpResponse2, 0);
                    return httpResponse2;
                }
                putMessage(streamId2, httpResponse2);
            } catch (Exception e3) {
                Channels.write(ctx, Channels.future(channel), (Object) new DefaultSpdyRstStreamFrame(streamId2, SpdyStreamStatus.PROTOCOL_ERROR));
            }
        } else if (msg instanceof SpdyHeadersFrame) {
            SpdyHeadersFrame spdyHeadersFrame = (SpdyHeadersFrame) msg;
            int streamId3 = spdyHeadersFrame.getStreamId();
            HttpMessage httpMessage = getMessage(streamId3);
            if (httpMessage == null) {
                return null;
            }
            if (!spdyHeadersFrame.isTruncated()) {
                Iterator i$ = spdyHeadersFrame.headers().iterator();
                while (i$.hasNext()) {
                    Entry<String, String> e4 = i$.next();
                    httpMessage.headers().add(e4.getKey(), (Object) e4.getValue());
                }
            }
            if (spdyHeadersFrame.isLast()) {
                HttpHeaders.setContentLength(httpMessage, (long) httpMessage.getContent().readableBytes());
                removeMessage(streamId3);
                return httpMessage;
            }
        } else if (msg instanceof SpdyDataFrame) {
            SpdyDataFrame spdyDataFrame = (SpdyDataFrame) msg;
            int streamId4 = spdyDataFrame.getStreamId();
            HttpMessage httpMessage2 = getMessage(streamId4);
            if (httpMessage2 == null) {
                return null;
            }
            ChannelBuffer content = httpMessage2.getContent();
            if (content.readableBytes() > this.maxContentLength - spdyDataFrame.getData().readableBytes()) {
                removeMessage(streamId4);
                throw new TooLongFrameException("HTTP content length exceeded " + this.maxContentLength + " bytes.");
            }
            if (content == ChannelBuffers.EMPTY_BUFFER) {
                content = ChannelBuffers.dynamicBuffer(channel.getConfig().getBufferFactory());
                content.writeBytes(spdyDataFrame.getData());
                httpMessage2.setContent(content);
            } else {
                content.writeBytes(spdyDataFrame.getData());
            }
            if (spdyDataFrame.isLast()) {
                HttpHeaders.setContentLength(httpMessage2, (long) content.readableBytes());
                removeMessage(streamId4);
                return httpMessage2;
            }
        } else if (msg instanceof SpdyRstStreamFrame) {
            removeMessage(((SpdyRstStreamFrame) msg).getStreamId());
        }
        return null;
    }

    private static HttpRequest createHttpRequest(int spdyVersion2, SpdyHeadersFrame requestFrame) throws Exception {
        HttpMethod method = SpdyHeaders.getMethod(spdyVersion2, requestFrame);
        String url = SpdyHeaders.getUrl(spdyVersion2, requestFrame);
        HttpVersion httpVersion = SpdyHeaders.getVersion(spdyVersion2, requestFrame);
        SpdyHeaders.removeMethod(spdyVersion2, requestFrame);
        SpdyHeaders.removeUrl(spdyVersion2, requestFrame);
        SpdyHeaders.removeVersion(spdyVersion2, requestFrame);
        HttpRequest httpRequest = new DefaultHttpRequest(httpVersion, method, url);
        SpdyHeaders.removeScheme(spdyVersion2, requestFrame);
        if (spdyVersion2 >= 3) {
            String host = SpdyHeaders.getHost(requestFrame);
            SpdyHeaders.removeHost(requestFrame);
            HttpHeaders.setHost(httpRequest, host);
        }
        Iterator i$ = requestFrame.headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = i$.next();
            httpRequest.headers().add(e.getKey(), (Object) e.getValue());
        }
        HttpHeaders.setKeepAlive(httpRequest, true);
        httpRequest.headers().remove(Names.TRANSFER_ENCODING);
        return httpRequest;
    }

    private static HttpResponse createHttpResponse(int spdyVersion2, SpdyHeadersFrame responseFrame) throws Exception {
        HttpResponseStatus status = SpdyHeaders.getStatus(spdyVersion2, responseFrame);
        HttpVersion version = SpdyHeaders.getVersion(spdyVersion2, responseFrame);
        SpdyHeaders.removeStatus(spdyVersion2, responseFrame);
        SpdyHeaders.removeVersion(spdyVersion2, responseFrame);
        HttpResponse httpResponse = new DefaultHttpResponse(version, status);
        Iterator i$ = responseFrame.headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> e = i$.next();
            httpResponse.headers().add(e.getKey(), (Object) e.getValue());
        }
        HttpHeaders.setKeepAlive(httpResponse, true);
        httpResponse.headers().remove(Names.TRANSFER_ENCODING);
        httpResponse.headers().remove(Names.TRAILER);
        return httpResponse;
    }
}