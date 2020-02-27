package org.jboss.netty.handler.codec.spdy;

import android.support.v4.view.ViewCompat;
import com.kakao.util.helper.CommonProtocol;
import java.net.SocketAddress;
import java.util.Iterator;
import java.util.Map.Entry;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.DownstreamMessageEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.http.HttpChunk;
import org.jboss.netty.handler.codec.http.HttpChunkTrailer;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMessage;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponse;
import org.jboss.netty.handler.codec.spdy.SpdyHttpHeaders.Names;

public class SpdyHttpEncoder implements ChannelDownstreamHandler {
    private volatile int currentStreamId;
    private final int spdyVersion;

    private static class SpdyFrameWriter implements ChannelFutureListener {
        private final ChannelHandlerContext ctx;
        private final MessageEvent e;

        SpdyFrameWriter(ChannelHandlerContext ctx2, MessageEvent e2) {
            this.ctx = ctx2;
            this.e = e2;
        }

        public void operationComplete(ChannelFuture future) throws Exception {
            if (future.isSuccess()) {
                this.ctx.sendDownstream(this.e);
            } else if (future.isCancelled()) {
                this.e.getFuture().cancel();
            } else {
                this.e.getFuture().setFailure(future.getCause());
            }
        }
    }

    public SpdyHttpEncoder(SpdyVersion spdyVersion2) {
        if (spdyVersion2 == null) {
            throw new NullPointerException("spdyVersion");
        }
        this.spdyVersion = spdyVersion2.getVersion();
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
        if (!(evt instanceof MessageEvent)) {
            ctx.sendDownstream(evt);
            return;
        }
        MessageEvent e = (MessageEvent) evt;
        Object msg = e.getMessage();
        if (msg instanceof HttpRequest) {
            HttpRequest httpRequest = (HttpRequest) msg;
            SpdySynStreamFrame spdySynStreamFrame = createSynStreamFrame(httpRequest);
            this.currentStreamId = spdySynStreamFrame.getStreamId();
            Channels.write(ctx, getMessageFuture(ctx, e, this.currentStreamId, httpRequest), spdySynStreamFrame, e.getRemoteAddress());
        } else if (msg instanceof HttpResponse) {
            HttpResponse httpResponse = (HttpResponse) msg;
            if (httpResponse.headers().contains(Names.ASSOCIATED_TO_STREAM_ID)) {
                SpdySynStreamFrame spdySynStreamFrame2 = createSynStreamFrame(httpResponse);
                this.currentStreamId = spdySynStreamFrame2.getStreamId();
                Channels.write(ctx, getMessageFuture(ctx, e, this.currentStreamId, httpResponse), spdySynStreamFrame2, e.getRemoteAddress());
                return;
            }
            SpdySynReplyFrame spdySynReplyFrame = createSynReplyFrame(httpResponse);
            this.currentStreamId = spdySynReplyFrame.getStreamId();
            Channels.write(ctx, getMessageFuture(ctx, e, this.currentStreamId, httpResponse), spdySynReplyFrame, e.getRemoteAddress());
        } else if (msg instanceof HttpChunk) {
            ChannelHandlerContext channelHandlerContext = ctx;
            writeChunk(channelHandlerContext, e.getFuture(), this.currentStreamId, (HttpChunk) msg, e.getRemoteAddress());
        } else {
            ctx.sendDownstream(evt);
        }
    }

    /* access modifiers changed from: protected */
    public void writeChunk(ChannelHandlerContext ctx, ChannelFuture future, int streamId, HttpChunk chunk, SocketAddress remoteAddress) {
        if (!chunk.isLast()) {
            getDataFuture(ctx, future, createSpdyDataFrames(streamId, chunk.getContent()), remoteAddress).setSuccess();
        } else if (chunk instanceof HttpChunkTrailer) {
            HttpHeaders trailers = ((HttpChunkTrailer) chunk).trailingHeaders();
            if (trailers.isEmpty()) {
                SpdyDataFrame spdyDataFrame = new DefaultSpdyDataFrame(streamId);
                spdyDataFrame.setLast(true);
                Channels.write(ctx, future, spdyDataFrame, remoteAddress);
                return;
            }
            SpdyHeadersFrame spdyHeadersFrame = new DefaultSpdyHeadersFrame(streamId);
            spdyHeadersFrame.setLast(true);
            Iterator i$ = trailers.iterator();
            while (i$.hasNext()) {
                Entry<String, String> entry = (Entry) i$.next();
                spdyHeadersFrame.headers().add(entry.getKey(), (Object) entry.getValue());
            }
            Channels.write(ctx, future, spdyHeadersFrame, remoteAddress);
        } else {
            SpdyDataFrame spdyDataFrame2 = new DefaultSpdyDataFrame(streamId);
            spdyDataFrame2.setLast(true);
            Channels.write(ctx, future, spdyDataFrame2, remoteAddress);
        }
    }

    private ChannelFuture getMessageFuture(ChannelHandlerContext ctx, MessageEvent e, int streamId, HttpMessage httpMessage) {
        if (!httpMessage.getContent().readable()) {
            return e.getFuture();
        }
        SpdyDataFrame[] spdyDataFrames = createSpdyDataFrames(streamId, httpMessage.getContent());
        if (spdyDataFrames.length > 0) {
            spdyDataFrames[spdyDataFrames.length - 1].setLast(true);
        }
        return getDataFuture(ctx, e.getFuture(), spdyDataFrames, e.getRemoteAddress());
    }

    private static ChannelFuture getDataFuture(ChannelHandlerContext ctx, ChannelFuture future, SpdyDataFrame[] spdyDataFrames, SocketAddress remoteAddress) {
        ChannelFuture dataFuture = future;
        int i = spdyDataFrames.length;
        while (true) {
            i--;
            if (i < 0) {
                return dataFuture;
            }
            ChannelFuture future2 = Channels.future(ctx.getChannel());
            future2.addListener(new SpdyFrameWriter(ctx, new DownstreamMessageEvent(ctx.getChannel(), dataFuture, spdyDataFrames[i], remoteAddress)));
            dataFuture = future2;
        }
    }

    private SpdySynStreamFrame createSynStreamFrame(HttpMessage httpMessage) throws Exception {
        boolean chunked = httpMessage.isChunked();
        int streamId = SpdyHttpHeaders.getStreamId(httpMessage);
        int associatedToStreamId = SpdyHttpHeaders.getAssociatedToStreamId(httpMessage);
        byte priority = SpdyHttpHeaders.getPriority(httpMessage);
        String URL = SpdyHttpHeaders.getUrl(httpMessage);
        String scheme = SpdyHttpHeaders.getScheme(httpMessage);
        SpdyHttpHeaders.removeStreamId(httpMessage);
        SpdyHttpHeaders.removeAssociatedToStreamId(httpMessage);
        SpdyHttpHeaders.removePriority(httpMessage);
        SpdyHttpHeaders.removeUrl(httpMessage);
        SpdyHttpHeaders.removeScheme(httpMessage);
        httpMessage.headers().remove("Connection");
        httpMessage.headers().remove("Keep-Alive");
        httpMessage.headers().remove("Proxy-Connection");
        httpMessage.headers().remove(HttpHeaders.Names.TRANSFER_ENCODING);
        SpdySynStreamFrame spdySynStreamFrame = new DefaultSpdySynStreamFrame(streamId, associatedToStreamId, priority);
        spdySynStreamFrame.setLast(!chunked && !httpMessage.getContent().readable());
        if (httpMessage instanceof HttpRequest) {
            HttpRequest httpRequest = (HttpRequest) httpMessage;
            SpdyHeaders.setMethod(this.spdyVersion, spdySynStreamFrame, httpRequest.getMethod());
            SpdyHeaders.setUrl(this.spdyVersion, spdySynStreamFrame, httpRequest.getUri());
            SpdyHeaders.setVersion(this.spdyVersion, spdySynStreamFrame, httpMessage.getProtocolVersion());
        }
        if (httpMessage instanceof HttpResponse) {
            SpdyHeaders.setStatus(this.spdyVersion, spdySynStreamFrame, ((HttpResponse) httpMessage).getStatus());
            SpdyHeaders.setUrl(this.spdyVersion, spdySynStreamFrame, URL);
            SpdyHeaders.setVersion(this.spdyVersion, spdySynStreamFrame, httpMessage.getProtocolVersion());
            spdySynStreamFrame.setUnidirectional(true);
        }
        String host = HttpHeaders.getHost(httpMessage);
        httpMessage.headers().remove("Host");
        SpdyHeaders.setHost(spdySynStreamFrame, host);
        if (scheme == null) {
            scheme = CommonProtocol.URL_SCHEME;
        }
        SpdyHeaders.setScheme(this.spdyVersion, spdySynStreamFrame, scheme);
        Iterator i$ = httpMessage.headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> entry = (Entry) i$.next();
            spdySynStreamFrame.headers().add(entry.getKey(), (Object) entry.getValue());
        }
        return spdySynStreamFrame;
    }

    private SpdySynReplyFrame createSynReplyFrame(HttpResponse httpResponse) throws Exception {
        boolean chunked = httpResponse.isChunked();
        int streamId = SpdyHttpHeaders.getStreamId(httpResponse);
        SpdyHttpHeaders.removeStreamId(httpResponse);
        httpResponse.headers().remove("Connection");
        httpResponse.headers().remove("Keep-Alive");
        httpResponse.headers().remove("Proxy-Connection");
        httpResponse.headers().remove(HttpHeaders.Names.TRANSFER_ENCODING);
        SpdySynReplyFrame spdySynReplyFrame = new DefaultSpdySynReplyFrame(streamId);
        spdySynReplyFrame.setLast(!chunked && !httpResponse.getContent().readable());
        SpdyHeaders.setStatus(this.spdyVersion, spdySynReplyFrame, httpResponse.getStatus());
        SpdyHeaders.setVersion(this.spdyVersion, spdySynReplyFrame, httpResponse.getProtocolVersion());
        Iterator i$ = httpResponse.headers().iterator();
        while (i$.hasNext()) {
            Entry<String, String> entry = (Entry) i$.next();
            spdySynReplyFrame.headers().add(entry.getKey(), (Object) entry.getValue());
        }
        return spdySynReplyFrame;
    }

    private SpdyDataFrame[] createSpdyDataFrames(int streamId, ChannelBuffer content) {
        int readableBytes = content.readableBytes();
        int count = readableBytes / ViewCompat.MEASURED_SIZE_MASK;
        if (readableBytes % ViewCompat.MEASURED_SIZE_MASK > 0) {
            count++;
        }
        SpdyDataFrame[] spdyDataFrames = new SpdyDataFrame[count];
        for (int i = 0; i < count; i++) {
            SpdyDataFrame spdyDataFrame = new DefaultSpdyDataFrame(streamId);
            spdyDataFrame.setData(content.readSlice(Math.min(content.readableBytes(), ViewCompat.MEASURED_SIZE_MASK)));
            spdyDataFrames[i] = spdyDataFrame;
        }
        return spdyDataFrames;
    }
}