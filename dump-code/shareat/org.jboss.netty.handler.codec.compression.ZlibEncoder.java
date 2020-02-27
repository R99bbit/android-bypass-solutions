package org.jboss.netty.handler.codec.compression;

import java.util.concurrent.atomic.AtomicBoolean;
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
import org.jboss.netty.util.internal.jzlib.JZlib;
import org.jboss.netty.util.internal.jzlib.ZStream;

public class ZlibEncoder extends OneToOneStrictEncoder implements LifeCycleAwareChannelHandler {
    private static final byte[] EMPTY_ARRAY = new byte[0];
    private volatile ChannelHandlerContext ctx;
    private final AtomicBoolean finished;
    private final ZStream z;

    public ZlibEncoder() {
        this(6);
    }

    public ZlibEncoder(int compressionLevel) {
        this(ZlibWrapper.ZLIB, compressionLevel);
    }

    public ZlibEncoder(ZlibWrapper wrapper) {
        this(wrapper, 6);
    }

    public ZlibEncoder(ZlibWrapper wrapper, int compressionLevel) {
        this(wrapper, compressionLevel, 15, 8);
    }

    public ZlibEncoder(ZlibWrapper wrapper, int compressionLevel, int windowBits, int memLevel) {
        this.z = new ZStream();
        this.finished = new AtomicBoolean();
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        } else if (windowBits < 9 || windowBits > 15) {
            throw new IllegalArgumentException("windowBits: " + windowBits + " (expected: 9-15)");
        } else if (memLevel < 1 || memLevel > 9) {
            throw new IllegalArgumentException("memLevel: " + memLevel + " (expected: 1-9)");
        } else if (wrapper == null) {
            throw new NullPointerException("wrapper");
        } else if (wrapper == ZlibWrapper.ZLIB_OR_NONE) {
            throw new IllegalArgumentException("wrapper '" + ZlibWrapper.ZLIB_OR_NONE + "' is not " + "allowed for compression.");
        } else {
            synchronized (this.z) {
                int resultCode = this.z.deflateInit(compressionLevel, windowBits, memLevel, ZlibUtil.convertWrapperType(wrapper));
                if (resultCode != 0) {
                    ZlibUtil.fail(this.z, "initialization failure", resultCode);
                }
            }
        }
    }

    public ZlibEncoder(byte[] dictionary) {
        this(6, dictionary);
    }

    public ZlibEncoder(int compressionLevel, byte[] dictionary) {
        this(compressionLevel, 15, 8, dictionary);
    }

    public ZlibEncoder(int compressionLevel, int windowBits, int memLevel, byte[] dictionary) {
        this.z = new ZStream();
        this.finished = new AtomicBoolean();
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        } else if (windowBits < 9 || windowBits > 15) {
            throw new IllegalArgumentException("windowBits: " + windowBits + " (expected: 9-15)");
        } else if (memLevel < 1 || memLevel > 9) {
            throw new IllegalArgumentException("memLevel: " + memLevel + " (expected: 1-9)");
        } else if (dictionary == null) {
            throw new NullPointerException("dictionary");
        } else {
            synchronized (this.z) {
                int resultCode = this.z.deflateInit(compressionLevel, windowBits, memLevel, JZlib.W_ZLIB);
                if (resultCode != 0) {
                    ZlibUtil.fail(this.z, "initialization failure", resultCode);
                } else {
                    int resultCode2 = this.z.deflateSetDictionary(dictionary, dictionary.length);
                    if (resultCode2 != 0) {
                        ZlibUtil.fail(this.z, "failed to set the dictionary", resultCode2);
                    }
                }
            }
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
        ChannelBuffer result;
        if (!(msg instanceof ChannelBuffer) || this.finished.get()) {
            return msg;
        }
        synchronized (this.z) {
            try {
                ChannelBuffer uncompressed = (ChannelBuffer) msg;
                byte[] in = new byte[uncompressed.readableBytes()];
                uncompressed.readBytes(in);
                this.z.next_in = in;
                this.z.next_in_index = 0;
                this.z.avail_in = in.length;
                byte[] out = new byte[(((int) Math.ceil(((double) in.length) * 1.001d)) + 12)];
                this.z.next_out = out;
                this.z.next_out_index = 0;
                this.z.avail_out = out.length;
                int resultCode = this.z.deflate(2);
                if (resultCode != 0) {
                    ZlibUtil.fail(this.z, "compression failure", resultCode);
                }
                if (this.z.next_out_index != 0) {
                    result = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(uncompressed.order(), out, 0, this.z.next_out_index);
                } else {
                    result = ChannelBuffers.EMPTY_BUFFER;
                }
            } finally {
                this.z.next_in = null;
                this.z.next_out = null;
            }
        }
        return result;
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
        ChannelFuture future;
        ChannelBuffer footer;
        if (!this.finished.compareAndSet(false, true)) {
            if (evt != null) {
                ctx2.sendDownstream(evt);
            }
            return Channels.succeededFuture(ctx2.getChannel());
        }
        synchronized (this.z) {
            try {
                this.z.next_in = EMPTY_ARRAY;
                this.z.next_in_index = 0;
                this.z.avail_in = 0;
                byte[] out = new byte[32];
                this.z.next_out = out;
                this.z.next_out_index = 0;
                this.z.avail_out = out.length;
                int resultCode = this.z.deflate(4);
                if (resultCode != 0 && resultCode != 1) {
                    future = Channels.failedFuture(ctx2.getChannel(), ZlibUtil.exception(this.z, "compression failure", resultCode));
                    footer = null;
                } else if (this.z.next_out_index != 0) {
                    future = Channels.future(ctx2.getChannel());
                    footer = ctx2.getChannel().getConfig().getBufferFactory().getBuffer(out, 0, this.z.next_out_index);
                } else {
                    future = Channels.future(ctx2.getChannel());
                    footer = ChannelBuffers.EMPTY_BUFFER;
                }
                this.z.deflateEnd();
                this.z.next_in = null;
                this.z.next_out = null;
            } catch (Throwable th) {
                this.z.deflateEnd();
                this.z.next_in = null;
                this.z.next_out = null;
                throw th;
            }
        }
        if (footer != null) {
            Channels.write(ctx2, future, (Object) footer);
        }
        if (evt == null) {
            return future;
        }
        future.addListener(new ChannelFutureListener() {
            public void operationComplete(ChannelFuture future) throws Exception {
                ctx2.sendDownstream(evt);
            }
        });
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