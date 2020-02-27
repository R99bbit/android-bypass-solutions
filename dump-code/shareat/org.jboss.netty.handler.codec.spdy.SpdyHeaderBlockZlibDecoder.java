package org.jboss.netty.handler.codec.spdy;

import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

final class SpdyHeaderBlockZlibDecoder extends SpdyHeaderBlockRawDecoder {
    private final ChannelBuffer decompressed = ChannelBuffers.buffer(4096);
    private final Inflater decompressor = new Inflater();

    public SpdyHeaderBlockZlibDecoder(SpdyVersion spdyVersion, int maxHeaderSize) {
        super(spdyVersion, maxHeaderSize);
    }

    /* access modifiers changed from: 0000 */
    public void decode(ChannelBuffer encoded, SpdyHeadersFrame frame) throws Exception {
        int numBytes;
        int len = setInput(encoded);
        do {
            numBytes = decompress(frame);
            if (this.decompressed.readable()) {
                break;
            }
        } while (numBytes > 0);
        if (this.decompressor.getRemaining() != 0) {
            throw new SpdyProtocolException((String) "client sent extra data beyond headers");
        }
        encoded.skipBytes(len);
    }

    private int setInput(ChannelBuffer compressed) {
        int len = compressed.readableBytes();
        if (compressed.hasArray()) {
            this.decompressor.setInput(compressed.array(), compressed.arrayOffset() + compressed.readerIndex(), len);
        } else {
            byte[] in = new byte[len];
            compressed.getBytes(compressed.readerIndex(), in);
            this.decompressor.setInput(in, 0, in.length);
        }
        return len;
    }

    private int decompress(SpdyHeadersFrame frame) throws Exception {
        byte[] out = this.decompressed.array();
        int off = this.decompressed.arrayOffset() + this.decompressed.writerIndex();
        try {
            int numBytes = this.decompressor.inflate(out, off, this.decompressed.writableBytes());
            if (numBytes == 0 && this.decompressor.needsDictionary()) {
                this.decompressor.setDictionary(SpdyCodecUtil.SPDY_DICT);
                numBytes = this.decompressor.inflate(out, off, this.decompressed.writableBytes());
            }
            if (frame != null) {
                this.decompressed.writerIndex(this.decompressed.writerIndex() + numBytes);
                super.decode(this.decompressed, frame);
                this.decompressed.discardReadBytes();
            }
            return numBytes;
        } catch (DataFormatException e) {
            throw new SpdyProtocolException("Received invalid header block", e);
        }
    }

    /* access modifiers changed from: 0000 */
    public void reset() {
        this.decompressed.clear();
        super.reset();
    }

    public void end() {
        this.decompressed.clear();
        this.decompressor.end();
        super.end();
    }
}