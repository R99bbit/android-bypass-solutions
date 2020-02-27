package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.buffer.ChannelBuffer;

abstract class SpdyHeaderBlockDecoder {
    /* access modifiers changed from: 0000 */
    public abstract void decode(ChannelBuffer channelBuffer, SpdyHeadersFrame spdyHeadersFrame) throws Exception;

    /* access modifiers changed from: 0000 */
    public abstract void end();

    /* access modifiers changed from: 0000 */
    public abstract void reset();

    SpdyHeaderBlockDecoder() {
    }

    static SpdyHeaderBlockDecoder newInstance(SpdyVersion spdyVersion, int maxHeaderSize) {
        return new SpdyHeaderBlockZlibDecoder(spdyVersion, maxHeaderSize);
    }
}