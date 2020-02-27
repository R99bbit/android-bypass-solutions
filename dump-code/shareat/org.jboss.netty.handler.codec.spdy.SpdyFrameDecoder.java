package org.jboss.netty.handler.codec.spdy;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.handler.codec.frame.FrameDecoder;

public class SpdyFrameDecoder extends FrameDecoder {
    private static final SpdyProtocolException INVALID_FRAME = new SpdyProtocolException((String) "Received invalid frame");
    private byte flags;
    private final SpdyHeaderBlockDecoder headerBlockDecoder;
    private int length;
    private final int maxChunkSize;
    private SpdyHeadersFrame spdyHeadersFrame;
    private SpdySettingsFrame spdySettingsFrame;
    private final int spdyVersion;
    private State state;
    private int streamId;
    private int type;
    private int version;

    private enum State {
        READ_COMMON_HEADER,
        READ_CONTROL_FRAME,
        READ_SETTINGS_FRAME,
        READ_HEADER_BLOCK_FRAME,
        READ_HEADER_BLOCK,
        READ_DATA_FRAME,
        DISCARD_FRAME,
        FRAME_ERROR
    }

    public SpdyFrameDecoder(SpdyVersion spdyVersion2) {
        this(spdyVersion2, 8192, 16384);
    }

    public SpdyFrameDecoder(SpdyVersion spdyVersion2, int maxChunkSize2, int maxHeaderSize) {
        this(spdyVersion2, maxChunkSize2, SpdyHeaderBlockDecoder.newInstance(spdyVersion2, maxHeaderSize));
    }

    protected SpdyFrameDecoder(SpdyVersion spdyVersion2, int maxChunkSize2, SpdyHeaderBlockDecoder headerBlockDecoder2) {
        super(false);
        if (spdyVersion2 == null) {
            throw new NullPointerException("spdyVersion");
        } else if (maxChunkSize2 <= 0) {
            throw new IllegalArgumentException("maxChunkSize must be a positive integer: " + maxChunkSize2);
        } else {
            this.spdyVersion = spdyVersion2.getVersion();
            this.maxChunkSize = maxChunkSize2;
            this.headerBlockDecoder = headerBlockDecoder2;
            this.state = State.READ_COMMON_HEADER;
        }
    }

    /* access modifiers changed from: protected */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer) throws Exception {
        switch (this.state) {
            case READ_COMMON_HEADER:
                this.state = readCommonHeader(buffer);
                if (this.state == State.FRAME_ERROR) {
                    if (this.version != this.spdyVersion) {
                        fireProtocolException(ctx, "Unsupported version: " + this.version);
                    } else {
                        fireInvalidFrameException(ctx);
                    }
                }
                if (this.length == 0) {
                    if (this.state == State.READ_DATA_FRAME) {
                        DefaultSpdyDataFrame defaultSpdyDataFrame = new DefaultSpdyDataFrame(this.streamId);
                        defaultSpdyDataFrame.setLast((this.flags & 1) != 0);
                        this.state = State.READ_COMMON_HEADER;
                        return defaultSpdyDataFrame;
                    }
                    this.state = State.READ_COMMON_HEADER;
                }
                return null;
            case READ_CONTROL_FRAME:
                try {
                    Object frame = readControlFrame(buffer);
                    if (frame == null) {
                        return frame;
                    }
                    this.state = State.READ_COMMON_HEADER;
                    return frame;
                } catch (IllegalArgumentException e) {
                    this.state = State.FRAME_ERROR;
                    fireInvalidFrameException(ctx);
                    return null;
                }
            case READ_SETTINGS_FRAME:
                if (this.spdySettingsFrame == null) {
                    if (buffer.readableBytes() < 4) {
                        return null;
                    }
                    int numEntries = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                    buffer.skipBytes(4);
                    this.length -= 4;
                    if ((this.length & 7) == 0 && (this.length >> 3) == numEntries) {
                        this.spdySettingsFrame = new DefaultSpdySettingsFrame();
                        this.spdySettingsFrame.setClearPreviouslyPersistedSettings((this.flags & 1) != 0);
                    } else {
                        this.state = State.FRAME_ERROR;
                        fireInvalidFrameException(ctx);
                        return null;
                    }
                }
                int readableEntries = Math.min(buffer.readableBytes() >> 3, this.length >> 3);
                for (int i = 0; i < readableEntries; i++) {
                    byte ID_flags = buffer.getByte(buffer.readerIndex());
                    int ID = SpdyCodecUtil.getUnsignedMedium(buffer, buffer.readerIndex() + 1);
                    int value = SpdyCodecUtil.getSignedInt(buffer, buffer.readerIndex() + 4);
                    buffer.skipBytes(8);
                    if (!this.spdySettingsFrame.isSet(ID)) {
                        this.spdySettingsFrame.setValue(ID, value, (ID_flags & 1) != 0, (ID_flags & 2) != 0);
                    }
                }
                this.length -= readableEntries * 8;
                if (this.length != 0) {
                    return null;
                }
                this.state = State.READ_COMMON_HEADER;
                SpdySettingsFrame spdySettingsFrame2 = this.spdySettingsFrame;
                this.spdySettingsFrame = null;
                return spdySettingsFrame2;
            case READ_HEADER_BLOCK_FRAME:
                try {
                    this.spdyHeadersFrame = readHeaderBlockFrame(buffer);
                    if (this.spdyHeadersFrame != null) {
                        if (this.length == 0) {
                            this.state = State.READ_COMMON_HEADER;
                            SpdyHeadersFrame spdyHeadersFrame2 = this.spdyHeadersFrame;
                            this.spdyHeadersFrame = null;
                            return spdyHeadersFrame2;
                        }
                        this.state = State.READ_HEADER_BLOCK;
                    }
                    return null;
                } catch (IllegalArgumentException e2) {
                    this.state = State.FRAME_ERROR;
                    fireInvalidFrameException(ctx);
                    return null;
                }
            case READ_HEADER_BLOCK:
                int compressedBytes = Math.min(buffer.readableBytes(), this.length);
                ChannelBuffer compressed = buffer.slice(buffer.readerIndex(), compressedBytes);
                try {
                    this.headerBlockDecoder.decode(compressed, this.spdyHeadersFrame);
                    int readBytes = compressedBytes - compressed.readableBytes();
                    buffer.skipBytes(readBytes);
                    this.length -= readBytes;
                    if (this.spdyHeadersFrame != null && (this.spdyHeadersFrame.isInvalid() || this.spdyHeadersFrame.isTruncated())) {
                        SpdyHeadersFrame spdyHeadersFrame3 = this.spdyHeadersFrame;
                        this.spdyHeadersFrame = null;
                        if (this.length != 0) {
                            return spdyHeadersFrame3;
                        }
                        this.headerBlockDecoder.reset();
                        this.state = State.READ_COMMON_HEADER;
                        return spdyHeadersFrame3;
                    } else if (this.length != 0) {
                        return null;
                    } else {
                        SpdyHeadersFrame spdyHeadersFrame4 = this.spdyHeadersFrame;
                        this.spdyHeadersFrame = null;
                        this.headerBlockDecoder.reset();
                        this.state = State.READ_COMMON_HEADER;
                        return spdyHeadersFrame4;
                    }
                } catch (Exception e3) {
                    this.state = State.FRAME_ERROR;
                    this.spdyHeadersFrame = null;
                    Channels.fireExceptionCaught(ctx, (Throwable) e3);
                    return null;
                }
            case READ_DATA_FRAME:
                if (this.streamId == 0) {
                    this.state = State.FRAME_ERROR;
                    fireProtocolException(ctx, "Received invalid data frame");
                    return null;
                }
                int dataLength = Math.min(this.maxChunkSize, this.length);
                if (buffer.readableBytes() < dataLength) {
                    return null;
                }
                DefaultSpdyDataFrame defaultSpdyDataFrame2 = new DefaultSpdyDataFrame(this.streamId);
                defaultSpdyDataFrame2.setData(buffer.readBytes(dataLength));
                this.length -= dataLength;
                if (this.length == 0) {
                    defaultSpdyDataFrame2.setLast((this.flags & 1) != 0);
                    this.state = State.READ_COMMON_HEADER;
                }
                return defaultSpdyDataFrame2;
            case DISCARD_FRAME:
                int numBytes = Math.min(buffer.readableBytes(), this.length);
                buffer.skipBytes(numBytes);
                this.length -= numBytes;
                if (this.length == 0) {
                    this.state = State.READ_COMMON_HEADER;
                }
                return null;
            case FRAME_ERROR:
                buffer.skipBytes(buffer.readableBytes());
                return null;
            default:
                throw new Error("Shouldn't reach here.");
        }
    }

    private State readCommonHeader(ChannelBuffer buffer) {
        boolean control;
        if (buffer.readableBytes() < 8) {
            return State.READ_COMMON_HEADER;
        }
        int frameOffset = buffer.readerIndex();
        int flagsOffset = frameOffset + 4;
        int lengthOffset = frameOffset + 5;
        buffer.skipBytes(8);
        if ((buffer.getByte(frameOffset) & 128) != 0) {
            control = true;
        } else {
            control = false;
        }
        this.flags = buffer.getByte(flagsOffset);
        this.length = SpdyCodecUtil.getUnsignedMedium(buffer, lengthOffset);
        if (control) {
            this.version = SpdyCodecUtil.getUnsignedShort(buffer, frameOffset) & 32767;
            this.type = SpdyCodecUtil.getUnsignedShort(buffer, frameOffset + 2);
            this.streamId = 0;
        } else {
            this.version = this.spdyVersion;
            this.type = 0;
            this.streamId = SpdyCodecUtil.getUnsignedInt(buffer, frameOffset);
        }
        if (this.version != this.spdyVersion || !isValidFrameHeader()) {
            return State.FRAME_ERROR;
        }
        if (willGenerateFrame()) {
            switch (this.type) {
                case 0:
                    return State.READ_DATA_FRAME;
                case 1:
                case 2:
                case 8:
                    return State.READ_HEADER_BLOCK_FRAME;
                case 4:
                    return State.READ_SETTINGS_FRAME;
                default:
                    return State.READ_CONTROL_FRAME;
            }
        } else if (this.length != 0) {
            return State.DISCARD_FRAME;
        } else {
            return State.READ_COMMON_HEADER;
        }
    }

    private Object readControlFrame(ChannelBuffer buffer) {
        switch (this.type) {
            case 3:
                if (buffer.readableBytes() < 8) {
                    return null;
                }
                int streamId2 = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                int statusCode = SpdyCodecUtil.getSignedInt(buffer, buffer.readerIndex() + 4);
                buffer.skipBytes(8);
                return new DefaultSpdyRstStreamFrame(streamId2, statusCode);
            case 6:
                if (buffer.readableBytes() < 4) {
                    return null;
                }
                int ID = SpdyCodecUtil.getSignedInt(buffer, buffer.readerIndex());
                buffer.skipBytes(4);
                return new DefaultSpdyPingFrame(ID);
            case 7:
                if (buffer.readableBytes() < 8) {
                    return null;
                }
                int lastGoodStreamID = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                int statusCode2 = SpdyCodecUtil.getSignedInt(buffer, buffer.readerIndex() + 4);
                buffer.skipBytes(8);
                return new DefaultSpdyGoAwayFrame(lastGoodStreamID, statusCode2);
            case 9:
                if (buffer.readableBytes() < 8) {
                    return null;
                }
                int streamId3 = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                int deltaWindowSize = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex() + 4);
                buffer.skipBytes(8);
                return new DefaultSpdyWindowUpdateFrame(streamId3, deltaWindowSize);
            default:
                throw new Error("Shouldn't reach here.");
        }
    }

    private SpdyHeadersFrame readHeaderBlockFrame(ChannelBuffer buffer) {
        boolean z;
        boolean z2 = true;
        switch (this.type) {
            case 1:
                if (buffer.readableBytes() < 10) {
                    return null;
                }
                int offset = buffer.readerIndex();
                buffer.skipBytes(10);
                this.length -= 10;
                SpdySynStreamFrame spdySynStreamFrame = new DefaultSpdySynStreamFrame(SpdyCodecUtil.getUnsignedInt(buffer, offset), SpdyCodecUtil.getUnsignedInt(buffer, offset + 4), (byte) ((buffer.getByte(offset + 8) >> 5) & 7));
                if ((this.flags & 1) != 0) {
                    z = true;
                } else {
                    z = false;
                }
                spdySynStreamFrame.setLast(z);
                if ((this.flags & 2) == 0) {
                    z2 = false;
                }
                spdySynStreamFrame.setUnidirectional(z2);
                return spdySynStreamFrame;
            case 2:
                if (buffer.readableBytes() < 4) {
                    return null;
                }
                int streamId2 = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                buffer.skipBytes(4);
                this.length -= 4;
                DefaultSpdySynReplyFrame defaultSpdySynReplyFrame = new DefaultSpdySynReplyFrame(streamId2);
                if ((this.flags & 1) == 0) {
                    z2 = false;
                }
                defaultSpdySynReplyFrame.setLast(z2);
                return defaultSpdySynReplyFrame;
            case 8:
                if (buffer.readableBytes() < 4) {
                    return null;
                }
                int streamId3 = SpdyCodecUtil.getUnsignedInt(buffer, buffer.readerIndex());
                buffer.skipBytes(4);
                this.length -= 4;
                DefaultSpdyHeadersFrame defaultSpdyHeadersFrame = new DefaultSpdyHeadersFrame(streamId3);
                if ((this.flags & 1) == 0) {
                    z2 = false;
                }
                defaultSpdyHeadersFrame.setLast(z2);
                return defaultSpdyHeadersFrame;
            default:
                throw new Error("Shouldn't reach here.");
        }
    }

    private boolean isValidFrameHeader() {
        switch (this.type) {
            case 0:
                if (this.streamId == 0) {
                    return false;
                }
                return true;
            case 1:
                if (this.length < 10) {
                    return false;
                }
                return true;
            case 2:
                if (this.length < 4) {
                    return false;
                }
                return true;
            case 3:
                if (this.flags == 0 && this.length == 8) {
                    return true;
                }
                return false;
            case 4:
                if (this.length < 4) {
                    return false;
                }
                return true;
            case 6:
                if (this.length != 4) {
                    return false;
                }
                return true;
            case 7:
                if (this.length != 8) {
                    return false;
                }
                return true;
            case 8:
                if (this.length < 4) {
                    return false;
                }
                return true;
            case 9:
                return this.length == 8;
            default:
                return true;
        }
    }

    private boolean willGenerateFrame() {
        switch (this.type) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 6:
            case 7:
            case 8:
            case 9:
                return true;
            default:
                return false;
        }
    }

    /* access modifiers changed from: protected */
    public void cleanup(ChannelHandlerContext ctx, ChannelStateEvent e) throws Exception {
        try {
            super.cleanup(ctx, e);
        } finally {
            this.headerBlockDecoder.end();
        }
    }

    private static void fireInvalidFrameException(ChannelHandlerContext ctx) {
        Channels.fireExceptionCaught(ctx, (Throwable) INVALID_FRAME);
    }

    private static void fireProtocolException(ChannelHandlerContext ctx, String message) {
        Channels.fireExceptionCaught(ctx, (Throwable) new SpdyProtocolException(message));
    }
}