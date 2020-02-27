package org.jboss.netty.handler.codec.spdy;

import java.util.zip.Deflater;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

class SpdyHeaderBlockZlibEncoder extends SpdyHeaderBlockRawEncoder {
    private final Deflater compressor;
    private boolean finished;

    public SpdyHeaderBlockZlibEncoder(SpdyVersion spdyVersion, int compressionLevel) {
        super(spdyVersion);
        if (compressionLevel < 0 || compressionLevel > 9) {
            throw new IllegalArgumentException("compressionLevel: " + compressionLevel + " (expected: 0-9)");
        }
        this.compressor = new Deflater(compressionLevel);
        this.compressor.setDictionary(SpdyCodecUtil.SPDY_DICT);
    }

    private int setInput(ChannelBuffer decompressed) {
        int len = decompressed.readableBytes();
        if (decompressed.hasArray()) {
            this.compressor.setInput(decompressed.array(), decompressed.arrayOffset() + decompressed.readerIndex(), len);
        } else {
            byte[] in = new byte[len];
            decompressed.getBytes(decompressed.readerIndex(), in);
            this.compressor.setInput(in, 0, in.length);
        }
        return len;
    }

    private void encode(ChannelBuffer compressed) {
        while (compressInto(compressed)) {
            compressed.ensureWritableBytes(compressed.capacity() << 1);
        }
    }

    private boolean compressInto(ChannelBuffer compressed) {
        int toWrite = compressed.writableBytes();
        int numBytes = this.compressor.deflate(compressed.array(), compressed.arrayOffset() + compressed.writerIndex(), toWrite, 2);
        compressed.writerIndex(compressed.writerIndex() + numBytes);
        return numBytes == toWrite;
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
                compressed = ChannelBuffers.dynamicBuffer(decompressed.readableBytes());
                int len = setInput(decompressed);
                encode(compressed);
                decompressed.skipBytes(len);
            }
        }
        return compressed;
    }

    public synchronized void end() {
        if (!this.finished) {
            this.finished = true;
            this.compressor.end();
            super.end();
        }
    }
}