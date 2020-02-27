package org.jboss.netty.handler.codec.serialization;

import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBufferOutputStream;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneEncoder;

public class CompatibleObjectEncoder extends OneToOneEncoder {
    private final AtomicReference<ChannelBuffer> buffer;
    private volatile ObjectOutputStream oout;
    private final int resetInterval;
    private int writtenObjects;

    public CompatibleObjectEncoder() {
        this(16);
    }

    public CompatibleObjectEncoder(int resetInterval2) {
        this.buffer = new AtomicReference<>();
        if (resetInterval2 < 0) {
            throw new IllegalArgumentException("resetInterval: " + resetInterval2);
        }
        this.resetInterval = resetInterval2;
    }

    /* access modifiers changed from: protected */
    public ObjectOutputStream newObjectOutputStream(OutputStream out) throws Exception {
        return new ObjectOutputStream(out);
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext context, Channel channel, Object msg) throws Exception {
        ChannelBuffer buffer2 = buffer(context);
        ObjectOutputStream oout2 = this.oout;
        if (this.resetInterval != 0) {
            this.writtenObjects++;
            if (this.writtenObjects % this.resetInterval == 0) {
                oout2.reset();
                buffer2.discardReadBytes();
            }
        }
        oout2.writeObject(msg);
        oout2.flush();
        return buffer2.readBytes(buffer2.readableBytes());
    }

    private ChannelBuffer buffer(ChannelHandlerContext ctx) throws Exception {
        ChannelBuffer buf = this.buffer.get();
        if (buf != null) {
            return buf;
        }
        ChannelBuffer buf2 = ChannelBuffers.dynamicBuffer(ctx.getChannel().getConfig().getBufferFactory());
        if (!this.buffer.compareAndSet(null, buf2)) {
            return this.buffer.get();
        }
        boolean success = false;
        try {
            this.oout = newObjectOutputStream(new ChannelBufferOutputStream(buf2));
            success = true;
        } finally {
            if (!success) {
                this.oout = null;
            }
        }
    }
}