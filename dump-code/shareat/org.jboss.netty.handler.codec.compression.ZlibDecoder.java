package org.jboss.netty.handler.codec.compression;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.oneone.OneToOneDecoder;
import org.jboss.netty.util.internal.jzlib.JZlib;
import org.jboss.netty.util.internal.jzlib.ZStream;

public class ZlibDecoder extends OneToOneDecoder {
    private byte[] dictionary;
    private volatile boolean finished;
    private final ZStream z;

    public ZlibDecoder() {
        this(ZlibWrapper.ZLIB);
    }

    public ZlibDecoder(ZlibWrapper wrapper) {
        this.z = new ZStream();
        if (wrapper == null) {
            throw new NullPointerException("wrapper");
        }
        synchronized (this.z) {
            int resultCode = this.z.inflateInit(ZlibUtil.convertWrapperType(wrapper));
            if (resultCode != 0) {
                ZlibUtil.fail(this.z, "initialization failure", resultCode);
            }
        }
    }

    public ZlibDecoder(byte[] dictionary2) {
        this.z = new ZStream();
        if (dictionary2 == null) {
            throw new NullPointerException("dictionary");
        }
        this.dictionary = dictionary2;
        synchronized (this.z) {
            int resultCode = this.z.inflateInit(JZlib.W_ZLIB);
            if (resultCode != 0) {
                ZlibUtil.fail(this.z, "initialization failure", resultCode);
            }
        }
    }

    public boolean isClosed() {
        return this.finished;
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, Object msg) throws Exception {
        if (!(msg instanceof ChannelBuffer) || this.finished) {
            return msg;
        }
        synchronized (this.z) {
            try {
                ChannelBuffer compressed = (ChannelBuffer) msg;
                byte[] in = new byte[compressed.readableBytes()];
                compressed.readBytes(in);
                this.z.next_in = in;
                this.z.next_in_index = 0;
                this.z.avail_in = in.length;
                byte[] out = new byte[(in.length << 1)];
                ChannelBuffer decompressed = ChannelBuffers.dynamicBuffer(compressed.order(), out.length, ctx.getChannel().getConfig().getBufferFactory());
                this.z.next_out = out;
                this.z.next_out_index = 0;
                this.z.avail_out = out.length;
                while (true) {
                    int resultCode = this.z.inflate(2);
                    if (this.z.next_out_index > 0) {
                        decompressed.writeBytes(out, 0, this.z.next_out_index);
                        this.z.avail_out = out.length;
                    }
                    this.z.next_out_index = 0;
                    switch (resultCode) {
                        case JZlib.Z_BUF_ERROR /*-5*/:
                            if (this.z.avail_in <= 0) {
                                break;
                            } else {
                                continue;
                            }
                        case 0:
                            break;
                        case 1:
                            this.finished = true;
                            this.z.inflateEnd();
                            break;
                        case 2:
                            if (this.dictionary != null) {
                                int resultCode2 = this.z.inflateSetDictionary(this.dictionary, this.dictionary.length);
                                if (resultCode2 == 0) {
                                    break;
                                } else {
                                    ZlibUtil.fail(this.z, "failed to set the dictionary", resultCode2);
                                    break;
                                }
                            } else {
                                ZlibUtil.fail(this.z, "decompression failure", resultCode);
                                continue;
                            }
                        default:
                            ZlibUtil.fail(this.z, "decompression failure", resultCode);
                            continue;
                    }
                }
                if (decompressed.writerIndex() != 0) {
                    this.z.next_in = null;
                    this.z.next_out = null;
                    return decompressed;
                }
                this.z.next_in = null;
                this.z.next_out = null;
                return null;
            } catch (Throwable th) {
                this.z.next_in = null;
                this.z.next_out = null;
                throw th;
            }
        }
    }
}