package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.replay.VoidEnum;

public class WebSocket00FrameDecoder extends ReplayingDecoder<VoidEnum> {
    private static final long DEFAULT_MAX_FRAME_SIZE = 16384;
    private final long maxFrameSize;
    private boolean receivedClosingHandshake;

    public WebSocket00FrameDecoder() {
        this(16384);
    }

    @Deprecated
    public WebSocket00FrameDecoder(int maxFrameSize2) {
        this.maxFrameSize = (long) maxFrameSize2;
    }

    public WebSocket00FrameDecoder(long maxFrameSize2) {
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
        return decodeTextFrame(buffer);
    }

    private WebSocketFrame decodeBinaryFrame(byte type, ChannelBuffer buffer) throws TooLongFrameException {
        byte b;
        long frameSize = 0;
        int lengthFieldSize = 0;
        do {
            b = buffer.readByte();
            frameSize = (frameSize << 7) | ((long) (b & Byte.MAX_VALUE));
            if (frameSize > this.maxFrameSize) {
                throw new TooLongFrameException();
            }
            lengthFieldSize++;
            if (lengthFieldSize > 8) {
                throw new TooLongFrameException();
            }
        } while ((b & 128) == 128);
        if (type != -1 || frameSize != 0) {
            return new BinaryWebSocketFrame(buffer.readBytes((int) frameSize));
        }
        this.receivedClosingHandshake = true;
        return new CloseWebSocketFrame();
    }

    private WebSocketFrame decodeTextFrame(ChannelBuffer buffer) throws TooLongFrameException {
        int ridx = buffer.readerIndex();
        int rbytes = actualReadableBytes();
        int delimPos = buffer.indexOf(ridx, ridx + rbytes, -1);
        if (delimPos != -1) {
            int frameSize = delimPos - ridx;
            if (((long) frameSize) > this.maxFrameSize) {
                throw new TooLongFrameException();
            }
            ChannelBuffer binaryData = buffer.readBytes(frameSize);
            buffer.skipBytes(1);
            if (binaryData.indexOf(binaryData.readerIndex(), binaryData.writerIndex(), -1) < 0) {
                return new TextWebSocketFrame(binaryData);
            }
            throw new IllegalArgumentException("a text frame should not contain 0xFF.");
        } else if (((long) rbytes) <= this.maxFrameSize) {
            return null;
        } else {
            throw new TooLongFrameException();
        }
    }
}