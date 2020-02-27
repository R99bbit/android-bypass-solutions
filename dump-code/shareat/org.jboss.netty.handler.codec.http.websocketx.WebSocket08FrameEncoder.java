package org.jboss.netty.handler.codec.http.websocketx;

import java.nio.ByteBuffer;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.TooLongFrameException;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;
import org.jboss.netty.logging.InternalLogger;
import org.jboss.netty.logging.InternalLoggerFactory;

public class WebSocket08FrameEncoder extends OneToOneEncoder {
    private static final byte OPCODE_BINARY = 2;
    private static final byte OPCODE_CLOSE = 8;
    private static final byte OPCODE_CONT = 0;
    private static final byte OPCODE_PING = 9;
    private static final byte OPCODE_PONG = 10;
    private static final byte OPCODE_TEXT = 1;
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(WebSocket08FrameEncoder.class);
    private final boolean maskPayload;

    public WebSocket08FrameEncoder(boolean maskPayload2) {
        this.maskPayload = maskPayload2;
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        byte opcode;
        ChannelBuffer header;
        ChannelBuffer body;
        if (!(msg instanceof WebSocketFrame)) {
            return msg;
        }
        WebSocketFrame frame = (WebSocketFrame) msg;
        ChannelBuffer data = frame.getBinaryData();
        if (data == null) {
            data = ChannelBuffers.EMPTY_BUFFER;
        }
        if (frame instanceof TextWebSocketFrame) {
            opcode = OPCODE_TEXT;
        } else if (frame instanceof PingWebSocketFrame) {
            opcode = 9;
        } else if (frame instanceof PongWebSocketFrame) {
            opcode = 10;
        } else if (frame instanceof CloseWebSocketFrame) {
            opcode = OPCODE_CLOSE;
        } else if (frame instanceof BinaryWebSocketFrame) {
            opcode = OPCODE_BINARY;
        } else if (frame instanceof ContinuationWebSocketFrame) {
            opcode = OPCODE_CONT;
        } else {
            throw new UnsupportedOperationException("Cannot encode frame of type: " + frame.getClass().getName());
        }
        int length = data.readableBytes();
        if (logger.isDebugEnabled()) {
            logger.debug("Encoding WebSocket Frame opCode=" + opcode + " length=" + length);
        }
        int b0 = 0;
        if (frame.isFinalFragment()) {
            b0 = 0 | 128;
        }
        int b02 = b0 | ((frame.getRsv() % 8) << 4) | (opcode % 128);
        if (opcode != 9 || length <= 125) {
            int maskLength = this.maskPayload ? 4 : 0;
            if (length <= 125) {
                header = ChannelBuffers.buffer(maskLength + 2);
                header.writeByte(b02);
                header.writeByte((byte) (this.maskPayload ? ((byte) length) | 128 : (byte) length));
            } else if (length <= 65535) {
                header = ChannelBuffers.buffer(maskLength + 4);
                header.writeByte(b02);
                header.writeByte(this.maskPayload ? 254 : 126);
                header.writeByte((length >>> 8) & 255);
                header.writeByte(length & 255);
            } else {
                header = ChannelBuffers.buffer(maskLength + 10);
                header.writeByte(b02);
                header.writeByte(this.maskPayload ? 255 : 127);
                header.writeLong((long) length);
            }
            if (this.maskPayload) {
                byte[] mask = ByteBuffer.allocate(4).putInt(Integer.valueOf((int) (Math.random() * 2.147483647E9d)).intValue()).array();
                header.writeBytes(mask);
                body = ChannelBuffers.buffer(length);
                int counter = 0;
                while (data.readableBytes() > 0) {
                    body.writeByte(mask[counter % 4] ^ data.readByte());
                    counter++;
                }
            } else {
                body = data;
            }
            return ChannelBuffers.wrappedBuffer(header, body);
        }
        throw new TooLongFrameException("invalid payload for PING (payload length must be <= 125, was " + length);
    }
}