package org.jboss.netty.handler.codec.http.websocket;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

@Deprecated
@Sharable
public class WebSocketFrameEncoder extends OneToOneEncoder {
    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (!(msg instanceof WebSocketFrame)) {
            return msg;
        }
        WebSocketFrame frame = (WebSocketFrame) msg;
        int type = frame.getType();
        if (frame.isText()) {
            ChannelBuffer data = frame.getBinaryData();
            ChannelBuffer encoded = channel.getConfig().getBufferFactory().getBuffer(data.order(), data.readableBytes() + 2);
            encoded.writeByte((byte) type);
            encoded.writeBytes(data, data.readerIndex(), data.readableBytes());
            encoded.writeByte(-1);
            return encoded;
        }
        ChannelBuffer data2 = frame.getBinaryData();
        int dataLen = data2.readableBytes();
        ChannelBuffer encoded2 = channel.getConfig().getBufferFactory().getBuffer(data2.order(), dataLen + 5);
        encoded2.writeByte((byte) type);
        int b1 = (dataLen >>> 28) & 127;
        int b2 = (dataLen >>> 14) & 127;
        int b3 = (dataLen >>> 7) & 127;
        int b4 = dataLen & 127;
        if (b1 != 0) {
            encoded2.writeByte(b1 | 128);
            encoded2.writeByte(b2 | 128);
            encoded2.writeByte(b3 | 128);
            encoded2.writeByte(b4);
        } else if (b2 != 0) {
            encoded2.writeByte(b2 | 128);
            encoded2.writeByte(b3 | 128);
            encoded2.writeByte(b4);
        } else if (b3 == 0) {
            encoded2.writeByte(b4);
        } else {
            encoded2.writeByte(b3 | 128);
            encoded2.writeByte(b4);
        }
        encoded2.writeBytes(data2, data2.readerIndex(), dataLen);
        return encoded2;
    }
}