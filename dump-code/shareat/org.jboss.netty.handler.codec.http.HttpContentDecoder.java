package org.jboss.netty.handler.codec.http;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.embedder.DecoderEmbedder;

public abstract class HttpContentDecoder extends SimpleChannelUpstreamHandler implements LifeCycleAwareChannelHandler {
    private DecoderEmbedder<ChannelBuffer> decoder;

    /* access modifiers changed from: protected */
    public abstract DecoderEmbedder<ChannelBuffer> newContentDecoder(String str) throws Exception;

    protected HttpContentDecoder() {
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        String contentEncoding;
        boolean hasContent;
        Object msg = e.getMessage();
        if ((msg instanceof HttpResponse) && ((HttpResponse) msg).getStatus().getCode() == 100) {
            ctx.sendUpstream(e);
        } else if (msg instanceof HttpMessage) {
            HttpMessage m = (HttpMessage) msg;
            finishDecode();
            String contentEncoding2 = m.headers().get("Content-Encoding");
            if (contentEncoding2 != null) {
                contentEncoding = contentEncoding2.trim();
            } else {
                contentEncoding = "identity";
            }
            if (m.isChunked() || m.getContent().readable()) {
                hasContent = true;
            } else {
                hasContent = false;
            }
            if (hasContent) {
                DecoderEmbedder<ChannelBuffer> newContentDecoder = newContentDecoder(contentEncoding);
                this.decoder = newContentDecoder;
                if (newContentDecoder != null) {
                    String targetContentEncoding = getTargetContentEncoding(contentEncoding);
                    if ("identity".equals(targetContentEncoding)) {
                        m.headers().remove("Content-Encoding");
                    } else {
                        m.headers().set((String) "Content-Encoding", (Object) targetContentEncoding);
                    }
                    if (!m.isChunked()) {
                        ChannelBuffer content = ChannelBuffers.wrappedBuffer(decode(m.getContent()), finishDecode());
                        m.setContent(content);
                        if (m.headers().contains("Content-Length")) {
                            m.headers().set((String) "Content-Length", (Object) Integer.toString(content.readableBytes()));
                        }
                    }
                }
            }
            ctx.sendUpstream(e);
        } else if (msg instanceof HttpChunk) {
            HttpChunk c = (HttpChunk) msg;
            ChannelBuffer content2 = c.getContent();
            if (this.decoder == null) {
                ctx.sendUpstream(e);
            } else if (!c.isLast()) {
                ChannelBuffer content3 = decode(content2);
                if (content3.readable()) {
                    c.setContent(content3);
                    ctx.sendUpstream(e);
                }
            } else {
                ChannelBuffer lastProduct = finishDecode();
                if (lastProduct.readable()) {
                    Channels.fireMessageReceived(ctx, (Object) new DefaultHttpChunk(lastProduct), e.getRemoteAddress());
                }
                ctx.sendUpstream(e);
            }
        } else {
            ctx.sendUpstream(e);
        }
    }

    public void channelClosed(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        finishDecode();
        super.channelClosed(ctx, e);
    }

    /* access modifiers changed from: protected */
    public String getTargetContentEncoding(String contentEncoding) throws Exception {
        return "identity";
    }

    private ChannelBuffer decode(ChannelBuffer buf) {
        this.decoder.offer(buf);
        return ChannelBuffers.wrappedBuffer((ChannelBuffer[]) this.decoder.pollAll(new ChannelBuffer[this.decoder.size()]));
    }

    private ChannelBuffer finishDecode() {
        ChannelBuffer result;
        if (this.decoder == null) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        if (this.decoder.finish()) {
            result = ChannelBuffers.wrappedBuffer((ChannelBuffer[]) this.decoder.pollAll(new ChannelBuffer[this.decoder.size()]));
        } else {
            result = ChannelBuffers.EMPTY_BUFFER;
        }
        this.decoder = null;
        return result;
    }

    public void beforeAdd(ChannelHandlerContext ctx) throws Exception {
    }

    public void afterAdd(ChannelHandlerContext ctx) throws Exception {
    }

    public void beforeRemove(ChannelHandlerContext ctx) throws Exception {
    }

    public void afterRemove(ChannelHandlerContext ctx) throws Exception {
        finishDecode();
    }
}