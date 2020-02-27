package org.jboss.netty.handler.codec.protobuf;

import com.google.protobuf.CodedInputStream;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.frame.CorruptedFrameException;
import org.jboss.netty.handler.codec.frame.FrameDecoder;

public class ProtobufVarint32FrameDecoder extends FrameDecoder {
    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        buffer.markReaderIndex();
        byte[] buf = new byte[5];
        int i = 0;
        while (i < buf.length) {
            if (!buffer.readable()) {
                buffer.resetReaderIndex();
                return null;
            }
            buf[i] = buffer.readByte();
            if (buf[i] >= 0) {
                int length = CodedInputStream.newInstance(buf, 0, i + 1).readRawVarint32();
                if (length < 0) {
                    throw new CorruptedFrameException("negative length: " + length);
                } else if (buffer.readableBytes() >= length) {
                    return buffer.readBytes(length);
                } else {
                    buffer.resetReaderIndex();
                    return null;
                }
            } else {
                i++;
            }
        }
        throw new CorruptedFrameException((String) "length wider than 32-bit");
    }
}