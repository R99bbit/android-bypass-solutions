package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.buffer.ChannelBuffer;

public class SpdyHeaderBlockRawDecoder extends SpdyHeaderBlockDecoder {
    private static final int LENGTH_FIELD_SIZE = 4;
    private int headerSize;
    private final int maxHeaderSize;
    private int numHeaders = -1;
    private final int version;

    public SpdyHeaderBlockRawDecoder(SpdyVersion spdyVersion, int maxHeaderSize2) {
        if (spdyVersion == null) {
            throw new NullPointerException("spdyVersion");
        }
        this.version = spdyVersion.getVersion();
        this.maxHeaderSize = maxHeaderSize2;
    }

    private int readLengthField(ChannelBuffer buffer) {
        int length = SpdyCodecUtil.getSignedInt(buffer, buffer.readerIndex());
        buffer.skipBytes(4);
        return length;
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: CFG modification limit reached, blocks count: 175 */
    /* JADX WARNING: Code restructure failed: missing block: B:40:0x00a5, code lost:
        r1 = r1 + r9;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:41:0x00a8, code lost:
        if (r1 <= r13.maxHeaderSize) goto L_0x00af;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:42:0x00aa, code lost:
        r15.setTruncated();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:44:0x00b3, code lost:
        if (r14.readableBytes() >= r9) goto L_0x00ba;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:45:0x00b5, code lost:
        r14.resetReaderIndex();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:0x00ba, code lost:
        r8 = new byte[r9];
        r14.readBytes(r8);
        r2 = 0;
        r6 = 0;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:47:0x00c1, code lost:
        if (r2 >= r9) goto L_0x00f6;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:49:0x00c4, code lost:
        if (r2 >= r8.length) goto L_0x00cd;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:51:0x00c8, code lost:
        if (r8[r2] == 0) goto L_0x00cd;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:52:0x00ca, code lost:
        r2 = r2 + 1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:54:0x00ce, code lost:
        if (r2 >= r8.length) goto L_0x00db;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:56:0x00d4, code lost:
        if (r8[r2 + 1] != 0) goto L_0x00db;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:57:0x00d6, code lost:
        r15.setInvalid();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:60:?, code lost:
        r15.headers().add(r3, (java.lang.Object) new java.lang.String(r8, r6, r2 - r6, "UTF-8"));
     */
    /* JADX WARNING: Code restructure failed: missing block: B:61:0x00ec, code lost:
        r2 = r2 + 1;
        r6 = r2;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:63:0x00f1, code lost:
        r15.setInvalid();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:64:0x00f6, code lost:
        r13.numHeaders--;
        r13.headerSize = r1;
     */
    public void decode(ChannelBuffer encoded, SpdyHeadersFrame frame) throws Exception {
        if (encoded == null) {
            throw new NullPointerException("encoded");
        } else if (frame == null) {
            throw new NullPointerException("frame");
        } else {
            if (this.numHeaders == -1) {
                if (encoded.readableBytes() >= 4) {
                    this.numHeaders = readLengthField(encoded);
                    if (this.numHeaders < 0) {
                        frame.setInvalid();
                    }
                }
            }
            loop0:
            while (true) {
                if (this.numHeaders <= 0) {
                    break loop0;
                }
                int headerSize2 = this.headerSize;
                encoded.markReaderIndex();
                if (encoded.readableBytes() >= 4) {
                    int nameLength = readLengthField(encoded);
                    if (nameLength > 0) {
                        int headerSize3 = headerSize2 + nameLength;
                        if (headerSize3 <= this.maxHeaderSize) {
                            if (encoded.readableBytes() >= nameLength) {
                                byte[] nameBytes = new byte[nameLength];
                                encoded.readBytes(nameBytes);
                                String name = new String(nameBytes, "UTF-8");
                                if (!frame.headers().contains(name)) {
                                    if (encoded.readableBytes() >= 4) {
                                        int valueLength = readLengthField(encoded);
                                        if (valueLength >= 0) {
                                            if (valueLength != 0) {
                                                break;
                                            }
                                            frame.headers().add(name, (Object) "");
                                            this.numHeaders--;
                                            this.headerSize = headerSize3;
                                        } else {
                                            frame.setInvalid();
                                            break loop0;
                                        }
                                    } else {
                                        encoded.resetReaderIndex();
                                        break loop0;
                                    }
                                } else {
                                    frame.setInvalid();
                                    break loop0;
                                }
                            } else {
                                encoded.resetReaderIndex();
                                break loop0;
                            }
                        } else {
                            frame.setTruncated();
                            break loop0;
                        }
                    } else {
                        frame.setInvalid();
                        break loop0;
                    }
                } else {
                    encoded.resetReaderIndex();
                    break loop0;
                }
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public void reset() {
        this.headerSize = 0;
        this.numHeaders = -1;
    }

    /* access modifiers changed from: 0000 */
    public void end() {
    }
}