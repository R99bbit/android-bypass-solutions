package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.compression.CompressionException;
import org.jboss.netty.util.internal.jzlib.JZlib;
import org.jboss.netty.util.internal.jzlib.ZStream;

class SpdyHeaderBlockJZlibEncoder extends SpdyHeaderBlockRawEncoder {
    private boolean finished;
    private final ZStream z = new ZStream();

    public SpdyHeaderBlockJZlibEncoder(SpdyVersion spdyVersion, int compressionLevel, int windowBits, int memLevel) {
        super(spdyVersion);
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        } else if (windowBits < 9 || windowBits > 15) {
            throw new IllegalArgumentException("windowBits: " + windowBits + " (expected: 9-15)");
        } else if (memLevel < 1 || memLevel > 9) {
            throw new IllegalArgumentException("memLevel: " + memLevel + " (expected: 1-9)");
        } else {
            int resultCode = this.z.deflateInit(compressionLevel, windowBits, memLevel, JZlib.W_ZLIB);
            if (resultCode != 0) {
                throw new CompressionException("failed to initialize an SPDY header block deflater: " + resultCode);
            }
            int resultCode2 = this.z.deflateSetDictionary(SpdyCodecUtil.SPDY_DICT, SpdyCodecUtil.SPDY_DICT.length);
            if (resultCode2 != 0) {
                throw new CompressionException("failed to set the SPDY dictionary: " + resultCode2);
            }
        }
    }

    private void setInput(ChannelBuffer decompressed) {
        byte[] in = new byte[decompressed.readableBytes()];
        decompressed.readBytes(in);
        this.z.next_in = in;
        this.z.next_in_index = 0;
        this.z.avail_in = in.length;
    }

    private void encode(ChannelBuffer compressed) {
        try {
            byte[] out = new byte[(((int) Math.ceil(((double) this.z.next_in.length) * 1.001d)) + 12)];
            this.z.next_out = out;
            this.z.next_out_index = 0;
            this.z.avail_out = out.length;
            int resultCode = this.z.deflate(2);
            if (resultCode != 0) {
                throw new CompressionException("compression failure: " + resultCode);
            }
            if (this.z.next_out_index != 0) {
                compressed.writeBytes(out, 0, this.z.next_out_index);
            }
        } finally {
            this.z.next_in = null;
            this.z.next_out = null;
        }
    }

    public synchronized ChannelBuffer encode(SpdyHeadersFrame frame) throws Exception {
        ChannelBuffer compressed;
        if (frame == null) {
            throw new IllegalArgumentException("frame");
        } else if (this.finished) {
            compressed = ChannelBuffers.EMPTY_BUFFER;
        } else {
            ChannelBuffer decompressed = super.encode(frame);
            if (decompressed.readableBytes() == 0) {
                compressed = ChannelBuffers.EMPTY_BUFFER;
            } else {
                compressed = ChannelBuffers.dynamicBuffer();
                setInput(decompressed);
                encode(compressed);
            }
        }
        return compressed;
    }

    public synchronized void end() {
        if (!this.finished) {
            this.finished = true;
            this.z.deflateEnd();
            this.z.next_in = null;
            this.z.next_out = null;
        }
    }
}