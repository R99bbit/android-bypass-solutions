package org.jboss.netty.handler.codec.spdy;

import java.nio.ByteOrder;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;

public class SpdyHeaderBlockRawEncoder extends SpdyHeaderBlockEncoder {
    private final int version;

    public SpdyHeaderBlockRawEncoder(SpdyVersion spdyVersion) {
        if (spdyVersion == null) {
            throw new NullPointerException("spdyVersion");
        }
        this.version = spdyVersion.getVersion();
    }

    private void setLengthField(ChannelBuffer buffer, int writerIndex, int length) {
        buffer.setInt(writerIndex, length);
    }

    private void writeLengthField(ChannelBuffer buffer, int length) {
        buffer.writeInt(length);
    }

    public ChannelBuffer encode(SpdyHeadersFrame headerFrame) throws Exception {
        Set<String> names = headerFrame.headers().names();
        int numHeaders = names.size();
        if (numHeaders == 0) {
            return ChannelBuffers.EMPTY_BUFFER;
        }
        if (numHeaders > 65535) {
            throw new IllegalArgumentException("header block contains too many headers");
        }
        ChannelBuffer headerBlock = ChannelBuffers.dynamicBuffer(ByteOrder.BIG_ENDIAN, 256);
        writeLengthField(headerBlock, numHeaders);
        for (String name : names) {
            byte[] nameBytes = name.getBytes("UTF-8");
            writeLengthField(headerBlock, nameBytes.length);
            headerBlock.writeBytes(nameBytes);
            int savedIndex = headerBlock.writerIndex();
            int valueLength = 0;
            writeLengthField(headerBlock, 0);
            for (String value : headerFrame.headers().getAll(name)) {
                byte[] valueBytes = value.getBytes("UTF-8");
                if (valueBytes.length > 0) {
                    headerBlock.writeBytes(valueBytes);
                    headerBlock.writeByte(0);
                    valueLength += valueBytes.length + 1;
                }
            }
            if (valueLength != 0) {
                valueLength--;
            }
            if (valueLength > 65535) {
                throw new IllegalArgumentException("header exceeds allowable length: " + name);
            } else if (valueLength > 0) {
                setLengthField(headerBlock, savedIndex, valueLength);
                headerBlock.writerIndex(headerBlock.writerIndex() - 1);
            }
        }
        return headerBlock;
    }

    /* access modifiers changed from: 0000 */
    public void end() {
    }
}