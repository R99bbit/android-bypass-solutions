package org.jboss.netty.handler.codec.compression;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.CRC32;
import java.util.zip.Deflater;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.LifeCycleAwareChannelHandler;
import org.jboss.netty.handler.codec.oneone.OneToOneStrictEncoder;

public class JdkZlibEncoder extends OneToOneStrictEncoder implements LifeCycleAwareChannelHandler {
    private static final byte[] gzipHeader = {31, -117, 8, 0, 0, 0, 0, 0, 0, 0};
    private final CRC32 crc;
    private volatile ChannelHandlerContext ctx;
    private final Deflater deflater;
    private final AtomicBoolean finished;
    private final boolean gzip;
    private final byte[] out;
    private boolean writeHeader;

    public JdkZlibEncoder() {
        this(6);
    }

    public JdkZlibEncoder(int compressionLevel) {
        this(ZlibWrapper.ZLIB, compressionLevel);
    }

    public JdkZlibEncoder(ZlibWrapper wrapper) {
        this(wrapper, 6);
    }

    public JdkZlibEncoder(ZlibWrapper wrapper, int compressionLevel) {
        boolean z;
        boolean z2 = true;
        this.out = new byte[8192];
        this.finished = new AtomicBoolean();
        this.crc = new CRC32();
        this.writeHeader = true;
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        } else if (wrapper == null) {
            throw new NullPointerException("wrapper");
        } else if (wrapper == ZlibWrapper.ZLIB_OR_NONE) {
            throw new IllegalArgumentException("wrapper '" + ZlibWrapper.ZLIB_OR_NONE + "' is not " + "allowed for compression.");
        } else {
            if (wrapper == ZlibWrapper.GZIP) {
                z = true;
            } else {
                z = false;
            }
            this.gzip = z;
            this.deflater = new Deflater(compressionLevel, wrapper == ZlibWrapper.ZLIB ? false : z2);
        }
    }

    public JdkZlibEncoder(byte[] dictionary) {
        this(6, dictionary);
    }

    public JdkZlibEncoder(int compressionLevel, byte[] dictionary) {
        this.out = new byte[8192];
        this.finished = new AtomicBoolean();
        this.crc = new CRC32();
        this.writeHeader = true;
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        } else if (dictionary == null) {
            throw new NullPointerException("dictionary");
        } else {
            this.gzip = false;
            this.deflater = new Deflater(compressionLevel);
            this.deflater.setDictionary(dictionary);
        }
    }

    public ChannelFuture close() {
        ChannelHandlerContext ctx2 = this.ctx;
        if (ctx2 != null) {
            return finishEncode(ctx2, null);
        }
        throw new IllegalStateException("not added to a pipeline");
    }

    public boolean isClosed() {
        return this.finished.get();
    }

    /* access modifiers changed from: protected */
    public Object encode(ChannelHandlerContext ctx2, Channel channel, Object msg) throws Exception {
        if (!(msg instanceof ChannelBuffer) || this.finished.get()) {
            return msg;
        }
        ChannelBuffer uncompressed = (ChannelBuffer) msg;
        byte[] in = new byte[uncompressed.readableBytes()];
        uncompressed.readBytes(in);
        ChannelBuffer compressed = ChannelBuffers.dynamicBuffer(((int) Math.ceil(((double) in.length) * 1.001d)) + 12, channel.getConfig().getBufferFactory());
        synchronized (this.deflater) {
            if (this.gzip) {
                this.crc.update(in);
                if (this.writeHeader) {
                    compressed.writeBytes(gzipHeader);
                    this.writeHeader = false;
                }
            }
            this.deflater.setInput(in);
            while (!this.deflater.needsInput()) {
                compressed.writeBytes(this.out, 0, this.deflater.deflate(this.out, 0, this.out.length, 2));
            }
        }
        return compressed;
    }

    public void handleDownstream(ChannelHandlerContext ctx2, ChannelEvent evt) throws Exception {
        if (evt instanceof ChannelStateEvent) {
            ChannelStateEvent e = (ChannelStateEvent) evt;
            switch (e.getState()) {
                case OPEN:
                case CONNECTED:
                case BOUND:
                    if (Boolean.FALSE.equals(e.getValue()) || e.getValue() == null) {
                        finishEncode(ctx2, evt);
                        return;
                    }
            }
        }
        super.handleDownstream(ctx2, evt);
    }

    private ChannelFuture finishEncode(final ChannelHandlerContext ctx2, final ChannelEvent evt) {
        ChannelFuture future = Channels.succeededFuture(ctx2.getChannel());
        if (!this.finished.compareAndSet(false, true)) {
            if (evt != null) {
                ctx2.sendDownstream(evt);
            }
            return future;
        }
        ChannelBuffer footer = ChannelBuffers.dynamicBuffer(ctx2.getChannel().getConfig().getBufferFactory());
        synchronized (this.deflater) {
            this.deflater.finish();
            while (!this.deflater.finished()) {
                footer.writeBytes(this.out, 0, this.deflater.deflate(this.out, 0, this.out.length));
            }
            if (this.gzip) {
                int crcValue = (int) this.crc.getValue();
                int uncBytes = this.deflater.getTotalIn();
                footer.writeByte(crcValue);
                footer.writeByte(crcValue >>> 8);
                footer.writeByte(crcValue >>> 16);
                footer.writeByte(crcValue >>> 24);
                footer.writeByte(uncBytes);
                footer.writeByte(uncBytes >>> 8);
                footer.writeByte(uncBytes >>> 16);
                footer.writeByte(uncBytes >>> 24);
            }
            this.deflater.end();
        }
        if (footer.readable()) {
            future = Channels.future(ctx2.getChannel());
            Channels.write(ctx2, future, (Object) footer);
        }
        if (evt != null) {
            future.addListener(new ChannelFutureListener() {
                public void operationComplete(ChannelFuture future) throws Exception {
                    ctx2.sendDownstream(evt);
                }
            });
        }
        return future;
    }

    public void beforeAdd(ChannelHandlerContext ctx2) throws Exception {
        this.ctx = ctx2;
    }

    public void afterAdd(ChannelHandlerContext ctx2) throws Exception {
    }

    public void beforeRemove(ChannelHandlerContext ctx2) throws Exception {
    }

    public void afterRemove(ChannelHandlerContext ctx2) throws Exception {
    }
}