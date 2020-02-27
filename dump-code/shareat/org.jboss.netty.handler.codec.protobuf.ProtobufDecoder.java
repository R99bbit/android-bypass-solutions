package org.jboss.netty.handler.codec.protobuf;

import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.MessageLite;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandler.Sharable;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;

@Sharable
public class ProtobufDecoder extends OneToOneDecoder {
    private static final boolean HAS_PARSER;
    private final ExtensionRegistry extensionRegistry;
    private final MessageLite prototype;

    static {
        boolean hasParser = false;
        try {
            MessageLite.class.getDeclaredMethod("getParserForType", new Class[0]);
            hasParser = true;
        } catch (Throwable th) {
        }
        HAS_PARSER = hasParser;
    }

    public ProtobufDecoder(MessageLite prototype2) {
        this(prototype2, null);
    }

    public ProtobufDecoder(MessageLite prototype2, ExtensionRegistry extensionRegistry2) {
        if (prototype2 == null) {
            throw new NullPointerException("prototype");
        }
        this.prototype = prototype2.getDefaultInstanceForType();
        this.extensionRegistry = extensionRegistry2;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        byte[] array;
        int offset;
        if (!(msg instanceof ChannelBuffer)) {
            return msg;
        }
        ChannelBuffer buf = (ChannelBuffer) msg;
        int length = buf.readableBytes();
        if (buf.hasArray()) {
            array = buf.array();
            offset = buf.arrayOffset() + buf.readerIndex();
        } else {
            array = new byte[length];
            buf.getBytes(buf.readerIndex(), array, 0, length);
            offset = 0;
        }
        if (this.extensionRegistry == null) {
            if (HAS_PARSER) {
                return this.prototype.getParserForType().parseFrom(array, offset, length);
            }
            return this.prototype.newBuilderForType().mergeFrom(array, offset, length).build();
        } else if (HAS_PARSER) {
            return this.prototype.getParserForType().parseFrom(array, offset, length, this.extensionRegistry);
        } else {
            return this.prototype.newBuilderForType().mergeFrom(array, offset, length, this.extensionRegistry).build();
        }
    }
}