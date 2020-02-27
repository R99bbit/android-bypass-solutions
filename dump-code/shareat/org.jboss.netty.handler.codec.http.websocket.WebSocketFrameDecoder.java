package org.jboss.netty.handler.codec.http.websocket;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.replay.VoidEnum;

@Deprecated
public class WebSocketFrameDecoder extends ReplayingDecoder<VoidEnum> {
    public static final int DEFAULT_MAX_FRAME_SIZE = 16384;
    private final int maxFrameSize;
    private boolean receivedClosingHandshake;

    public WebSocketFrameDecoder() {
        this(16384);
    }

    public WebSocketFrameDecoder(int maxFrameSize2) {
        this.maxFrameSize = maxFrameSize2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, VoidEnum state) throws Exception {
        if (this.receivedClosingHandshake) {
            buffer.skipBytes(actualReadableBytes());
            return null;
        }
        byte type = buffer.readByte();
        if ((type & 128) == 128) {
            return decodeBinaryFrame(type, buffer);
        }
        return decodeTextFrame(type, buffer);
    }

    private WebSocketFrame decodeBinaryFrame(int type, ChannelBuffer buffer) throws TooLongFrameException {
        byte b;
        long frameSize = 0;
        int lengthFieldSize = 0;
        do {
            b = buffer.readByte();
            frameSize = (frameSize << 7) | ((long) (b & Byte.MAX_VALUE));
            if (frameSize > ((long) this.maxFrameSize)) {
                throw new TooLongFrameException();
            }
            lengthFieldSize++;
            if (lengthFieldSize > 8) {
                throw new TooLongFrameException();
            }
        } while ((b & 128) == 128);
        if (type == 255 && frameSize == 0) {
            this.receivedClosingHandshake = true;
        }
        return new DefaultWebSocketFrame(type, buffer.readBytes((int) frameSize));
    }

    private WebSocketFrame decodeTextFrame(int type, ChannelBuffer buffer) throws TooLongFrameException {
        int ridx = buffer.readerIndex();
        int rbytes = actualReadableBytes();
        int delimPos = buffer.indexOf(ridx, ridx + rbytes, -1);
        if (delimPos != -1) {
            int frameSize = delimPos - ridx;
            if (frameSize > this.maxFrameSize) {
                throw new TooLongFrameException();
            }
            ChannelBuffer binaryData = buffer.readBytes(frameSize);
            buffer.skipBytes(1);
            return new DefaultWebSocketFrame(type, binaryData);
        } else if (rbytes <= this.maxFrameSize) {
            return null;
        } else {
            throw new TooLongFrameException();
        }
    }
}