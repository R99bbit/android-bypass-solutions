package org.jboss.netty.handler.codec.spdy;

import java.net.SocketAddress;
import java.nio.channels.ClosedChannelException;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.ChannelStateEvent;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.ExceptionEvent;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;

public class SpdySessionHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {
    private static final int DEFAULT_MAX_CONCURRENT_STREAMS = Integer.MAX_VALUE;
    private static final int DEFAULT_WINDOW_SIZE = 65536;
    private static final SpdyProtocolException PROTOCOL_EXCEPTION = new SpdyProtocolException();
    private volatile ChannelFutureListener closeSessionFutureListener;
    private final Object flowControlLock = new Object();
    private volatile int initialReceiveWindowSize = 65536;
    private volatile int initialSendWindowSize = 65536;
    private volatile int lastGoodStreamId;
    private volatile int localConcurrentStreams = Integer.MAX_VALUE;
    private final int minorVersion;
    private final AtomicInteger pings = new AtomicInteger();
    private volatile boolean receivedGoAwayFrame;
    private volatile int remoteConcurrentStreams = Integer.MAX_VALUE;
    private volatile boolean sentGoAwayFrame;
    private final boolean server;
    private final boolean sessionFlowControl;
    private final SpdySession spdySession = new SpdySession(this.initialSendWindowSize, this.initialReceiveWindowSize);

    private static final class ClosingChannelFutureListener implements ChannelFutureListener {
        private final ChannelHandlerContext ctx;
        private final ChannelStateEvent e;

        ClosingChannelFutureListener(ChannelHandlerContext ctx2, ChannelStateEvent e2) {
            this.ctx = ctx2;
            this.e = e2;
        }

        public void operationComplete(ChannelFuture sentGoAwayFuture) throws Exception {
            if (!(sentGoAwayFuture.getCause() instanceof ClosedChannelException)) {
                Channels.close(this.ctx, this.e.getFuture());
            } else {
                this.e.getFuture().setSuccess();
            }
        }
    }

    public SpdySessionHandler(SpdyVersion spdyVersion, boolean server2) {
        if (spdyVersion == null) {
            throw new NullPointerException("spdyVersion");
        }
        this.server = server2;
        this.minorVersion = spdyVersion.getMinorVersion();
        this.sessionFlowControl = spdyVersion.useSessionFlowControl();
    }

    public void messageReceived(ChannelHandlerContext ctx, MessageEvent e) throws Exception {
        Object msg = e.getMessage();
        if (msg instanceof SpdyDataFrame) {
            SpdyDataFrame spdyDataFrame = (SpdyDataFrame) msg;
            int streamId = spdyDataFrame.getStreamId();
            if (this.sessionFlowControl) {
                int newSessionWindowSize = this.spdySession.updateReceiveWindowSize(0, spdyDataFrame.getData().readableBytes() * -1);
                if (newSessionWindowSize < 0) {
                    issueSessionError(ctx, e.getChannel(), e.getRemoteAddress(), SpdySessionStatus.PROTOCOL_ERROR);
                    return;
                } else if (newSessionWindowSize <= this.initialReceiveWindowSize / 2) {
                    int deltaWindowSize = this.initialReceiveWindowSize - newSessionWindowSize;
                    this.spdySession.updateReceiveWindowSize(0, deltaWindowSize);
                    DefaultSpdyWindowUpdateFrame defaultSpdyWindowUpdateFrame = new DefaultSpdyWindowUpdateFrame(0, deltaWindowSize);
                    Channels.write(ctx, Channels.future(e.getChannel()), defaultSpdyWindowUpdateFrame, e.getRemoteAddress());
                }
            }
            if (!this.spdySession.isActiveStream(streamId)) {
                if (streamId <= this.lastGoodStreamId) {
                    issueStreamError(ctx, e.getRemoteAddress(), streamId, SpdyStreamStatus.PROTOCOL_ERROR);
                    return;
                } else if (!this.sentGoAwayFrame) {
                    issueStreamError(ctx, e.getRemoteAddress(), streamId, SpdyStreamStatus.INVALID_STREAM);
                    return;
                } else {
                    return;
                }
            } else if (this.spdySession.isRemoteSideClosed(streamId)) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId, SpdyStreamStatus.STREAM_ALREADY_CLOSED);
                return;
            } else if (isRemoteInitiatedId(streamId) || this.spdySession.hasReceivedReply(streamId)) {
                int newWindowSize = this.spdySession.updateReceiveWindowSize(streamId, spdyDataFrame.getData().readableBytes() * -1);
                if (newWindowSize < this.spdySession.getReceiveWindowSizeLowerBound(streamId)) {
                    issueStreamError(ctx, e.getRemoteAddress(), streamId, SpdyStreamStatus.FLOW_CONTROL_ERROR);
                    return;
                }
                if (newWindowSize < 0) {
                    while (spdyDataFrame.getData().readableBytes() > this.initialReceiveWindowSize) {
                        SpdyDataFrame partialDataFrame = new DefaultSpdyDataFrame(streamId);
                        partialDataFrame.setData(spdyDataFrame.getData().readSlice(this.initialReceiveWindowSize));
                        Channels.fireMessageReceived(ctx, (Object) partialDataFrame, e.getRemoteAddress());
                    }
                }
                if (newWindowSize <= this.initialReceiveWindowSize / 2 && !spdyDataFrame.isLast()) {
                    int deltaWindowSize2 = this.initialReceiveWindowSize - newWindowSize;
                    this.spdySession.updateReceiveWindowSize(streamId, deltaWindowSize2);
                    DefaultSpdyWindowUpdateFrame defaultSpdyWindowUpdateFrame2 = new DefaultSpdyWindowUpdateFrame(streamId, deltaWindowSize2);
                    Channels.write(ctx, Channels.future(e.getChannel()), defaultSpdyWindowUpdateFrame2, e.getRemoteAddress());
                }
                if (spdyDataFrame.isLast()) {
                    halfCloseStream(streamId, true, e.getFuture());
                }
            } else {
                issueStreamError(ctx, e.getRemoteAddress(), streamId, SpdyStreamStatus.PROTOCOL_ERROR);
                return;
            }
        } else if (msg instanceof SpdySynStreamFrame) {
            SpdySynStreamFrame spdySynStreamFrame = (SpdySynStreamFrame) msg;
            int streamId2 = spdySynStreamFrame.getStreamId();
            if (spdySynStreamFrame.isInvalid() || !isRemoteInitiatedId(streamId2) || this.spdySession.isActiveStream(streamId2)) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId2, SpdyStreamStatus.PROTOCOL_ERROR);
                return;
            }
            if (streamId2 <= this.lastGoodStreamId) {
                issueSessionError(ctx, e.getChannel(), e.getRemoteAddress(), SpdySessionStatus.PROTOCOL_ERROR);
                return;
            }
            if (!acceptStream(streamId2, spdySynStreamFrame.getPriority(), spdySynStreamFrame.isLast(), spdySynStreamFrame.isUnidirectional())) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId2, SpdyStreamStatus.REFUSED_STREAM);
                return;
            }
        } else if (msg instanceof SpdySynReplyFrame) {
            SpdySynReplyFrame spdySynReplyFrame = (SpdySynReplyFrame) msg;
            int streamId3 = spdySynReplyFrame.getStreamId();
            if (spdySynReplyFrame.isInvalid() || isRemoteInitiatedId(streamId3) || this.spdySession.isRemoteSideClosed(streamId3)) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId3, SpdyStreamStatus.INVALID_STREAM);
                return;
            } else if (this.spdySession.hasReceivedReply(streamId3)) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId3, SpdyStreamStatus.STREAM_IN_USE);
                return;
            } else {
                this.spdySession.receivedReply(streamId3);
                if (spdySynReplyFrame.isLast()) {
                    halfCloseStream(streamId3, true, e.getFuture());
                }
            }
        } else if (msg instanceof SpdyRstStreamFrame) {
            removeStream(((SpdyRstStreamFrame) msg).getStreamId(), e.getFuture());
        } else if (msg instanceof SpdySettingsFrame) {
            SpdySettingsFrame spdySettingsFrame = (SpdySettingsFrame) msg;
            int settingsMinorVersion = spdySettingsFrame.getValue(0);
            if (settingsMinorVersion < 0 || settingsMinorVersion == this.minorVersion) {
                int newConcurrentStreams = spdySettingsFrame.getValue(4);
                if (newConcurrentStreams >= 0) {
                    this.remoteConcurrentStreams = newConcurrentStreams;
                }
                if (spdySettingsFrame.isPersisted(7)) {
                    spdySettingsFrame.removeValue(7);
                }
                spdySettingsFrame.setPersistValue(7, false);
                int newInitialWindowSize = spdySettingsFrame.getValue(7);
                if (newInitialWindowSize >= 0) {
                    updateInitialSendWindowSize(newInitialWindowSize);
                }
            } else {
                issueSessionError(ctx, e.getChannel(), e.getRemoteAddress(), SpdySessionStatus.PROTOCOL_ERROR);
                return;
            }
        } else if (msg instanceof SpdyPingFrame) {
            SpdyPingFrame spdyPingFrame = (SpdyPingFrame) msg;
            if (isRemoteInitiatedId(spdyPingFrame.getId())) {
                Channels.write(ctx, Channels.future(e.getChannel()), spdyPingFrame, e.getRemoteAddress());
                return;
            } else if (this.pings.get() != 0) {
                this.pings.getAndDecrement();
            } else {
                return;
            }
        } else if (msg instanceof SpdyGoAwayFrame) {
            this.receivedGoAwayFrame = true;
        } else if (msg instanceof SpdyHeadersFrame) {
            SpdyHeadersFrame spdyHeadersFrame = (SpdyHeadersFrame) msg;
            int streamId4 = spdyHeadersFrame.getStreamId();
            if (spdyHeadersFrame.isInvalid()) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId4, SpdyStreamStatus.PROTOCOL_ERROR);
                return;
            } else if (this.spdySession.isRemoteSideClosed(streamId4)) {
                issueStreamError(ctx, e.getRemoteAddress(), streamId4, SpdyStreamStatus.INVALID_STREAM);
                return;
            } else if (spdyHeadersFrame.isLast()) {
                halfCloseStream(streamId4, true, e.getFuture());
            }
        } else if (msg instanceof SpdyWindowUpdateFrame) {
            SpdyWindowUpdateFrame spdyWindowUpdateFrame = (SpdyWindowUpdateFrame) msg;
            int streamId5 = spdyWindowUpdateFrame.getStreamId();
            int deltaWindowSize3 = spdyWindowUpdateFrame.getDeltaWindowSize();
            if (streamId5 != 0 && this.spdySession.isLocalSideClosed(streamId5)) {
                return;
            }
            if (this.spdySession.getSendWindowSize(streamId5) <= Integer.MAX_VALUE - deltaWindowSize3) {
                updateSendWindowSize(ctx, streamId5, deltaWindowSize3);
                return;
            } else if (streamId5 == 0) {
                issueSessionError(ctx, e.getChannel(), e.getRemoteAddress(), SpdySessionStatus.PROTOCOL_ERROR);
                return;
            } else {
                issueStreamError(ctx, e.getRemoteAddress(), streamId5, SpdyStreamStatus.FLOW_CONTROL_ERROR);
                return;
            }
        }
        super.messageReceived(ctx, e);
    }

    public void exceptionCaught(ChannelHandlerContext ctx, ExceptionEvent e) throws Exception {
        if (e.getCause() instanceof SpdyProtocolException) {
            issueSessionError(ctx, e.getChannel(), null, SpdySessionStatus.PROTOCOL_ERROR);
        }
        super.exceptionCaught(ctx, e);
    }

    /* JADX WARNING: Code restructure failed: missing block: B:45:0x0187, code lost:
        if (r18.isLast() == false) goto L_0x019a;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:46:0x0189, code lost:
        halfCloseStream(r25, false, r6.getFuture());
     */
    public void handleDownstream(ChannelHandlerContext ctx, ChannelEvent evt) throws Exception {
        if (evt instanceof ChannelStateEvent) {
            ChannelStateEvent e = (ChannelStateEvent) evt;
            switch (e.getState()) {
                case OPEN:
                case CONNECTED:
                case BOUND:
                    if (Boolean.FALSE.equals(e.getValue()) || e.getValue() == null) {
                        sendGoAwayFrame(ctx, e);
                        return;
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
            int streamId = spdyDataFrame.getStreamId();
            if (this.spdySession.isLocalSideClosed(streamId)) {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            }
            synchronized (this.flowControlLock) {
                int dataLength = spdyDataFrame.getData().readableBytes();
                int sendWindowSize = this.spdySession.getSendWindowSize(streamId);
                if (this.sessionFlowControl) {
                    sendWindowSize = Math.min(sendWindowSize, this.spdySession.getSendWindowSize(0));
                }
                if (sendWindowSize <= 0) {
                    this.spdySession.putPendingWrite(streamId, e2);
                    return;
                } else if (sendWindowSize < dataLength) {
                    this.spdySession.updateSendWindowSize(streamId, sendWindowSize * -1);
                    if (this.sessionFlowControl) {
                        this.spdySession.updateSendWindowSize(0, sendWindowSize * -1);
                    }
                    SpdyDataFrame partialDataFrame = new DefaultSpdyDataFrame(streamId);
                    partialDataFrame.setData(spdyDataFrame.getData().readSlice(sendWindowSize));
                    this.spdySession.putPendingWrite(streamId, e2);
                    ChannelFuture writeFuture = Channels.future(e2.getChannel());
                    final SocketAddress remoteAddress = e2.getRemoteAddress();
                    final ChannelHandlerContext context = ctx;
                    ChannelFuture future = e2.getFuture();
                    AnonymousClass1 r0 = new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture future) throws Exception {
                            if (!future.isSuccess()) {
                                SpdySessionHandler.this.issueSessionError(context, future.getChannel(), remoteAddress, SpdySessionStatus.INTERNAL_ERROR);
                            }
                        }
                    };
                    future.addListener(r0);
                    Channels.write(ctx, writeFuture, partialDataFrame, remoteAddress);
                    return;
                } else {
                    this.spdySession.updateSendWindowSize(streamId, dataLength * -1);
                    if (this.sessionFlowControl) {
                        this.spdySession.updateSendWindowSize(0, dataLength * -1);
                    }
                    final SocketAddress remoteAddress2 = e2.getRemoteAddress();
                    final ChannelHandlerContext context2 = ctx;
                    ChannelFuture future2 = e2.getFuture();
                    AnonymousClass2 r02 = new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture future) throws Exception {
                            if (!future.isSuccess()) {
                                SpdySessionHandler.this.issueSessionError(context2, future.getChannel(), remoteAddress2, SpdySessionStatus.INTERNAL_ERROR);
                            }
                        }
                    };
                    future2.addListener(r02);
                }
            }
        } else if (msg instanceof SpdySynStreamFrame) {
            SpdySynStreamFrame spdySynStreamFrame = (SpdySynStreamFrame) msg;
            int streamId2 = spdySynStreamFrame.getStreamId();
            if (isRemoteInitiatedId(streamId2)) {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            }
            if (!acceptStream(streamId2, spdySynStreamFrame.getPriority(), spdySynStreamFrame.isUnidirectional(), spdySynStreamFrame.isLast())) {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            }
        } else if (msg instanceof SpdySynReplyFrame) {
            SpdySynReplyFrame spdySynReplyFrame = (SpdySynReplyFrame) msg;
            int streamId3 = spdySynReplyFrame.getStreamId();
            if (!isRemoteInitiatedId(streamId3) || this.spdySession.isLocalSideClosed(streamId3)) {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            } else if (spdySynReplyFrame.isLast()) {
                halfCloseStream(streamId3, false, e2.getFuture());
            }
        } else if (msg instanceof SpdyRstStreamFrame) {
            removeStream(((SpdyRstStreamFrame) msg).getStreamId(), e2.getFuture());
        } else if (msg instanceof SpdySettingsFrame) {
            SpdySettingsFrame spdySettingsFrame = (SpdySettingsFrame) msg;
            int settingsMinorVersion = spdySettingsFrame.getValue(0);
            if (settingsMinorVersion < 0 || settingsMinorVersion == this.minorVersion) {
                int newConcurrentStreams = spdySettingsFrame.getValue(4);
                if (newConcurrentStreams >= 0) {
                    this.localConcurrentStreams = newConcurrentStreams;
                }
                if (spdySettingsFrame.isPersisted(7)) {
                    spdySettingsFrame.removeValue(7);
                }
                spdySettingsFrame.setPersistValue(7, false);
                int newInitialWindowSize = spdySettingsFrame.getValue(7);
                if (newInitialWindowSize >= 0) {
                    updateInitialReceiveWindowSize(newInitialWindowSize);
                }
            } else {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            }
        } else if (msg instanceof SpdyPingFrame) {
            SpdyPingFrame spdyPingFrame = (SpdyPingFrame) msg;
            if (isRemoteInitiatedId(spdyPingFrame.getId())) {
                e2.getFuture().setFailure(new IllegalArgumentException("invalid PING ID: " + spdyPingFrame.getId()));
                return;
            }
            this.pings.getAndIncrement();
        } else if (msg instanceof SpdyGoAwayFrame) {
            e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
            return;
        } else if (msg instanceof SpdyHeadersFrame) {
            SpdyHeadersFrame spdyHeadersFrame = (SpdyHeadersFrame) msg;
            int streamId4 = spdyHeadersFrame.getStreamId();
            if (this.spdySession.isLocalSideClosed(streamId4)) {
                e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
                return;
            } else if (spdyHeadersFrame.isLast()) {
                halfCloseStream(streamId4, false, e2.getFuture());
            }
        } else if (msg instanceof SpdyWindowUpdateFrame) {
            e2.getFuture().setFailure(PROTOCOL_EXCEPTION);
            return;
        }
        ctx.sendDownstream(evt);
    }

    /* access modifiers changed from: private */
    public void issueSessionError(ChannelHandlerContext ctx, Channel channel, SocketAddress remoteAddress, SpdySessionStatus status) {
        sendGoAwayFrame(ctx, channel, remoteAddress, status).addListener(ChannelFutureListener.CLOSE);
    }

    private void issueStreamError(ChannelHandlerContext ctx, SocketAddress remoteAddress, int streamId, SpdyStreamStatus status) {
        boolean fireMessageReceived = !this.spdySession.isRemoteSideClosed(streamId);
        ChannelFuture future = Channels.future(ctx.getChannel());
        removeStream(streamId, future);
        SpdyRstStreamFrame spdyRstStreamFrame = new DefaultSpdyRstStreamFrame(streamId, status);
        Channels.write(ctx, future, spdyRstStreamFrame, remoteAddress);
        if (fireMessageReceived) {
            Channels.fireMessageReceived(ctx, (Object) spdyRstStreamFrame, remoteAddress);
        }
    }

    private boolean isRemoteInitiatedId(int id) {
        boolean serverId = SpdyCodecUtil.isServerId(id);
        return (this.server && !serverId) || (!this.server && serverId);
    }

    private synchronized void updateInitialSendWindowSize(int newInitialWindowSize) {
        this.initialSendWindowSize = newInitialWindowSize;
        this.spdySession.updateAllSendWindowSizes(newInitialWindowSize - this.initialSendWindowSize);
    }

    private synchronized void updateInitialReceiveWindowSize(int newInitialWindowSize) {
        this.initialReceiveWindowSize = newInitialWindowSize;
        this.spdySession.updateAllReceiveWindowSizes(newInitialWindowSize - this.initialReceiveWindowSize);
    }

    private synchronized boolean acceptStream(int streamId, byte priority, boolean remoteSideClosed, boolean localSideClosed) {
        boolean z = false;
        synchronized (this) {
            if (!this.receivedGoAwayFrame && !this.sentGoAwayFrame) {
                boolean remote = isRemoteInitiatedId(streamId);
                if (this.spdySession.numActiveStreams(remote) < (remote ? this.localConcurrentStreams : this.remoteConcurrentStreams)) {
                    this.spdySession.acceptStream(streamId, priority, remoteSideClosed, localSideClosed, this.initialSendWindowSize, this.initialReceiveWindowSize, remote);
                    if (remote) {
                        this.lastGoodStreamId = streamId;
                    }
                    z = true;
                }
            }
        }
        return z;
    }

    private void halfCloseStream(int streamId, boolean remote, ChannelFuture future) {
        if (remote) {
            this.spdySession.closeRemoteSide(streamId, isRemoteInitiatedId(streamId));
        } else {
            this.spdySession.closeLocalSide(streamId, isRemoteInitiatedId(streamId));
        }
        if (this.closeSessionFutureListener != null && this.spdySession.noActiveStreams()) {
            future.addListener(this.closeSessionFutureListener);
        }
    }

    private void removeStream(int streamId, ChannelFuture future) {
        this.spdySession.removeStream(streamId, isRemoteInitiatedId(streamId));
        if (this.closeSessionFutureListener != null && this.spdySession.noActiveStreams()) {
            future.addListener(this.closeSessionFutureListener);
        }
    }

    private void updateSendWindowSize(ChannelHandlerContext ctx, int streamId, int deltaWindowSize) {
        int newWindowSize;
        synchronized (this.flowControlLock) {
            int newWindowSize2 = this.spdySession.updateSendWindowSize(streamId, deltaWindowSize);
            if (this.sessionFlowControl && streamId != 0) {
                newWindowSize2 = Math.min(newWindowSize2, this.spdySession.getSendWindowSize(0));
            }
            while (newWindowSize > 0) {
                MessageEvent e = this.spdySession.getPendingWrite(streamId);
                if (e == null) {
                    break;
                }
                SpdyDataFrame spdyDataFrame = (SpdyDataFrame) e.getMessage();
                int dataFrameSize = spdyDataFrame.getData().readableBytes();
                int writeStreamId = spdyDataFrame.getStreamId();
                if (this.sessionFlowControl && streamId == 0) {
                    newWindowSize = Math.min(newWindowSize, this.spdySession.getSendWindowSize(writeStreamId));
                }
                if (newWindowSize >= dataFrameSize) {
                    this.spdySession.removePendingWrite(writeStreamId);
                    newWindowSize = this.spdySession.updateSendWindowSize(writeStreamId, dataFrameSize * -1);
                    if (this.sessionFlowControl) {
                        newWindowSize = Math.min(newWindowSize, this.spdySession.updateSendWindowSize(0, dataFrameSize * -1));
                    }
                    final SocketAddress remoteAddress = e.getRemoteAddress();
                    final ChannelHandlerContext context = ctx;
                    e.getFuture().addListener(new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture future) throws Exception {
                            if (!future.isSuccess()) {
                                SpdySessionHandler.this.issueSessionError(context, future.getChannel(), remoteAddress, SpdySessionStatus.INTERNAL_ERROR);
                            }
                        }
                    });
                    if (spdyDataFrame.isLast()) {
                        halfCloseStream(writeStreamId, false, e.getFuture());
                    }
                    Channels.write(ctx, e.getFuture(), spdyDataFrame, e.getRemoteAddress());
                } else {
                    this.spdySession.updateSendWindowSize(writeStreamId, newWindowSize * -1);
                    if (this.sessionFlowControl) {
                        this.spdySession.updateSendWindowSize(0, newWindowSize * -1);
                    }
                    SpdyDataFrame partialDataFrame = new DefaultSpdyDataFrame(writeStreamId);
                    partialDataFrame.setData(spdyDataFrame.getData().readSlice(newWindowSize));
                    ChannelFuture writeFuture = Channels.future(e.getChannel());
                    final SocketAddress remoteAddress2 = e.getRemoteAddress();
                    final ChannelHandlerContext context2 = ctx;
                    e.getFuture().addListener(new ChannelFutureListener() {
                        public void operationComplete(ChannelFuture future) throws Exception {
                            if (!future.isSuccess()) {
                                SpdySessionHandler.this.issueSessionError(context2, future.getChannel(), remoteAddress2, SpdySessionStatus.INTERNAL_ERROR);
                            }
                        }
                    });
                    Channels.write(ctx, writeFuture, partialDataFrame, remoteAddress2);
                    newWindowSize = 0;
                }
            }
        }
    }

    private void sendGoAwayFrame(ChannelHandlerContext ctx, ChannelStateEvent e) {
        if (!e.getChannel().isConnected()) {
            ctx.sendDownstream(e);
            return;
        }
        ChannelFuture future = sendGoAwayFrame(ctx, e.getChannel(), null, SpdySessionStatus.OK);
        if (this.spdySession.noActiveStreams()) {
            future.addListener(new ClosingChannelFutureListener(ctx, e));
        } else {
            this.closeSessionFutureListener = new ClosingChannelFutureListener(ctx, e);
        }
    }

    private synchronized ChannelFuture sendGoAwayFrame(ChannelHandlerContext ctx, Channel channel, SocketAddress remoteAddress, SpdySessionStatus status) {
        ChannelFuture future;
        if (!this.sentGoAwayFrame) {
            this.sentGoAwayFrame = true;
            SpdyGoAwayFrame spdyGoAwayFrame = new DefaultSpdyGoAwayFrame(this.lastGoodStreamId, status);
            future = Channels.future(channel);
            Channels.write(ctx, future, spdyGoAwayFrame, remoteAddress);
        } else {
            future = Channels.succeededFuture(channel);
        }
        return future;
    }
}