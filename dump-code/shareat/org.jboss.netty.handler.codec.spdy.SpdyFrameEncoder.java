package org.jboss.netty.handler.codec.spdy;

import java.nio.ByteOrder;
import java.util.Set;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.handler.codec.http.HttpConstants;

public class SpdyFrameEncoder implements ChannelDownstreamHandler {
    private final SpdyHeaderBlockEncoder headerBlockEncoder;
    private final int version;

    public SpdyFrameEncoder(SpdyVersion spdyVersion) {
        this(spdyVersion, 6, 15, 8);
    }

    public SpdyFrameEncoder(SpdyVersion spdyVersion, int compressionLevel, int windowBits, int memLevel) {
        this(spdyVersion, SpdyHeaderBlockEncoder.newInstance(spdyVersion, compressionLevel, windowBits, memLevel));
    }

    protected SpdyFrameEncoder(SpdyVersion spdyVersion, SpdyHeaderBlockEncoder headerBlockEncoder2) {
        if (spdyVersion == null) {
            throw new NullPointerException("spdyVersion");
        }
        this.version = spdyVersion.getVersion();
        this.headerBlockEncoder = headerBlockEncoder2;
    }

    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
        if (evt instanceof ChannelStateEvent) {
            ChannelStateEvent e = (ChannelStateEvent) evt;
            switch (e.getState()) {
                case OPEN:
                case CONNECTED:
                case BOUND:
                    if (Boolean.FALSE.equals(e.getValue()) || e.getValue() == null) {
                        synchronized (this.headerBlockEncoder) {
                            this.headerBlockEncoder.end();
                        }
                        break;
                    }
            }
        }
        if (!(evt instanceof MessageEvent)) {
            ctx.sendDownstream(evt);
            return;
        }
        MessageEvent e2 = (MessageEvent) evt;
        Object msg = e2.getMessage();
        if (msg instanceof SpdyDataFrame) {
            SpdyDataFrame spdyDataFrame = (SpdyDataFrame) msg;
            ChannelBuffer data = spdyDataFrame.getData();
            byte flags = spdyDataFrame.isLast() ? (byte) 1 : 0;
            ChannelBuffer header = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 8);
            header.writeInt(spdyDataFrame.getStreamId() & ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED);
            header.writeByte(flags);
            header.writeMedium(data.readableBytes());
            Channels.write(ctx, e2.getFuture(), ChannelBuffers.wrappedBuffer(header, data), e2.getRemoteAddress());
        } else if (msg instanceof SpdySynStreamFrame) {
            synchronized (this.headerBlockEncoder) {
                SpdySynStreamFrame spdySynStreamFrame = (SpdySynStreamFrame) msg;
                ChannelBuffer data2 = this.headerBlockEncoder.encode(spdySynStreamFrame);
                byte flags2 = spdySynStreamFrame.isLast() ? (byte) 1 : 0;
                if (spdySynStreamFrame.isUnidirectional()) {
                    flags2 = (byte) (flags2 | 2);
                }
                ChannelBuffer frame = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 18);
                frame.writeShort(this.version | 32768);
                frame.writeShort(1);
                frame.writeByte(flags2);
                frame.writeMedium(data2.readableBytes() + 10);
                frame.writeInt(spdySynStreamFrame.getStreamId());
                frame.writeInt(spdySynStreamFrame.getAssociatedToStreamId());
                frame.writeShort((spdySynStreamFrame.getPriority() & 255) << HttpConstants.CR);
                Channels.write(ctx, e2.getFuture(), ChannelBuffers.wrappedBuffer(frame, data2), e2.getRemoteAddress());
            }
        } else if (msg instanceof SpdySynReplyFrame) {
            synchronized (this.headerBlockEncoder) {
                SpdySynReplyFrame spdySynReplyFrame = (SpdySynReplyFrame) msg;
                ChannelBuffer data3 = this.headerBlockEncoder.encode(spdySynReplyFrame);
                byte flags3 = spdySynReplyFrame.isLast() ? (byte) 1 : 0;
                ChannelBuffer frame2 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 12);
                frame2.writeShort(this.version | 32768);
                frame2.writeShort(2);
                frame2.writeByte(flags3);
                frame2.writeMedium(data3.readableBytes() + 4);
                frame2.writeInt(spdySynReplyFrame.getStreamId());
                Channels.write(ctx, e2.getFuture(), ChannelBuffers.wrappedBuffer(frame2, data3), e2.getRemoteAddress());
            }
        } else if (msg instanceof SpdyRstStreamFrame) {
            SpdyRstStreamFrame spdyRstStreamFrame = (SpdyRstStreamFrame) msg;
            ChannelBuffer frame3 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 16);
            frame3.writeShort(this.version | 32768);
            frame3.writeShort(3);
            frame3.writeInt(8);
            frame3.writeInt(spdyRstStreamFrame.getStreamId());
            frame3.writeInt(spdyRstStreamFrame.getStatus().getCode());
            Channels.write(ctx, e2.getFuture(), frame3, e2.getRemoteAddress());
        } else if (msg instanceof SpdySettingsFrame) {
            SpdySettingsFrame spdySettingsFrame = (SpdySettingsFrame) msg;
            byte flags4 = spdySettingsFrame.clearPreviouslyPersistedSettings() ? (byte) 1 : 0;
            Set<Integer> IDs = spdySettingsFrame.getIds();
            int numEntries = IDs.size();
            int length = (numEntries * 8) + 4;
            ChannelBuffer frame4 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, length + 8);
            frame4.writeShort(this.version | 32768);
            frame4.writeShort(4);
            frame4.writeByte(flags4);
            frame4.writeMedium(length);
            frame4.writeInt(numEntries);
            for (Integer id : IDs) {
                byte ID_flags = 0;
                if (spdySettingsFrame.isPersistValue(id.intValue())) {
                    ID_flags = (byte) 1;
                }
                if (spdySettingsFrame.isPersisted(id.intValue())) {
                    ID_flags = (byte) (ID_flags | 2);
                }
                frame4.writeByte(ID_flags);
                frame4.writeMedium(id.intValue());
                frame4.writeInt(spdySettingsFrame.getValue(id.intValue()));
            }
            Channels.write(ctx, e2.getFuture(), frame4, e2.getRemoteAddress());
        } else if (msg instanceof SpdyPingFrame) {
            ChannelBuffer frame5 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 12);
            frame5.writeShort(this.version | 32768);
            frame5.writeShort(6);
            frame5.writeInt(4);
            frame5.writeInt(((SpdyPingFrame) msg).getId());
            Channels.write(ctx, e2.getFuture(), frame5, e2.getRemoteAddress());
        } else if (msg instanceof SpdyGoAwayFrame) {
            SpdyGoAwayFrame spdyGoAwayFrame = (SpdyGoAwayFrame) msg;
            ChannelBuffer frame6 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 16);
            frame6.writeShort(this.version | 32768);
            frame6.writeShort(7);
            frame6.writeInt(8);
            frame6.writeInt(spdyGoAwayFrame.getLastGoodStreamId());
            frame6.writeInt(spdyGoAwayFrame.getStatus().getCode());
            Channels.write(ctx, e2.getFuture(), frame6, e2.getRemoteAddress());
        } else if (msg instanceof SpdyHeadersFrame) {
            synchronized (this.headerBlockEncoder) {
                SpdyHeadersFrame spdyHeadersFrame = (SpdyHeadersFrame) msg;
                ChannelBuffer data4 = this.headerBlockEncoder.encode(spdyHeadersFrame);
                byte flags5 = spdyHeadersFrame.isLast() ? (byte) 1 : 0;
                ChannelBuffer frame7 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 12);
                frame7.writeShort(this.version | 32768);
                frame7.writeShort(8);
                frame7.writeByte(flags5);
                frame7.writeMedium(data4.readableBytes() + 4);
                frame7.writeInt(spdyHeadersFrame.getStreamId());
                Channels.write(ctx, e2.getFuture(), ChannelBuffers.wrappedBuffer(frame7, data4), e2.getRemoteAddress());
            }
        } else if (msg instanceof SpdyWindowUpdateFrame) {
            SpdyWindowUpdateFrame spdyWindowUpdateFrame = (SpdyWindowUpdateFrame) msg;
            ChannelBuffer frame8 = ChannelBuffers.buffer(ByteOrder.BIG_ENDIAN, 16);
            frame8.writeShort(this.version | 32768);
            frame8.writeShort(9);
            frame8.writeInt(8);
            frame8.writeInt(spdyWindowUpdateFrame.getStreamId());
            frame8.writeInt(spdyWindowUpdateFrame.getDeltaWindowSize());
            Channels.write(ctx, e2.getFuture(), frame8, e2.getRemoteAddress());
        } else {
            ctx.sendDownstream(evt);
        }
    }
}