package org.jboss.netty.handler.codec.spdy;

import java.util.Comparator;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.jboss.netty.channel.MessageEvent;

final class SpdySession {
    private static final SpdyProtocolException STREAM_CLOSED = new SpdyProtocolException((String) "Stream closed");
    private final AtomicInteger activeLocalStreams = new AtomicInteger();
    private final AtomicInteger activeRemoteStreams = new AtomicInteger();
    /* access modifiers changed from: private */
    public final Map<Integer, StreamState> activeStreams = new ConcurrentHashMap();
    private final AtomicInteger receiveWindowSize;
    private final AtomicInteger sendWindowSize;

    private final class PriorityComparator implements Comparator<Integer> {
        PriorityComparator() {
        }

        public int compare(Integer id1, Integer id2) {
            return ((StreamState) SpdySession.this.activeStreams.get(id1)).getPriority() - ((StreamState) SpdySession.this.activeStreams.get(id2)).getPriority();
        }
    }

    private static final class StreamState {
        private volatile boolean localSideClosed;
        private final ConcurrentLinkedQueue<MessageEvent> pendingWriteQueue = new ConcurrentLinkedQueue<>();
        private final byte priority;
        private final AtomicInteger receiveWindowSize;
        private volatile int receiveWindowSizeLowerBound;
        private boolean receivedReply;
        private volatile boolean remoteSideClosed;
        private final AtomicInteger sendWindowSize;

        StreamState(byte priority2, boolean remoteSideClosed2, boolean localSideClosed2, int sendWindowSize2, int receiveWindowSize2) {
            this.priority = priority2;
            this.remoteSideClosed = remoteSideClosed2;
            this.localSideClosed = localSideClosed2;
            this.sendWindowSize = new AtomicInteger(sendWindowSize2);
            this.receiveWindowSize = new AtomicInteger(receiveWindowSize2);
        }

        /* access modifiers changed from: 0000 */
        public byte getPriority() {
            return this.priority;
        }

        /* access modifiers changed from: 0000 */
        public boolean isRemoteSideClosed() {
            return this.remoteSideClosed;
        }

        /* access modifiers changed from: 0000 */
        public void closeRemoteSide() {
            this.remoteSideClosed = true;
        }

        /* access modifiers changed from: 0000 */
        public boolean isLocalSideClosed() {
            return this.localSideClosed;
        }

        /* access modifiers changed from: 0000 */
        public void closeLocalSide() {
            this.localSideClosed = true;
        }

        /* access modifiers changed from: 0000 */
        public boolean hasReceivedReply() {
            return this.receivedReply;
        }

        /* access modifiers changed from: 0000 */
        public void receivedReply() {
            this.receivedReply = true;
        }

        /* access modifiers changed from: 0000 */
        public int getSendWindowSize() {
            return this.sendWindowSize.get();
        }

        /* access modifiers changed from: 0000 */
        public int updateSendWindowSize(int deltaWindowSize) {
            return this.sendWindowSize.addAndGet(deltaWindowSize);
        }

        /* access modifiers changed from: 0000 */
        public int updateReceiveWindowSize(int deltaWindowSize) {
            return this.receiveWindowSize.addAndGet(deltaWindowSize);
        }

        /* access modifiers changed from: 0000 */
        public int getReceiveWindowSizeLowerBound() {
            return this.receiveWindowSizeLowerBound;
        }

        /* access modifiers changed from: 0000 */
        public void setReceiveWindowSizeLowerBound(int receiveWindowSizeLowerBound2) {
            this.receiveWindowSizeLowerBound = receiveWindowSizeLowerBound2;
        }

        /* access modifiers changed from: 0000 */
        public boolean putPendingWrite(MessageEvent evt) {
            return this.pendingWriteQueue.offer(evt);
        }

        /* access modifiers changed from: 0000 */
        public MessageEvent getPendingWrite() {
            return this.pendingWriteQueue.peek();
        }

        /* access modifiers changed from: 0000 */
        public MessageEvent removePendingWrite() {
            return this.pendingWriteQueue.poll();
        }
    }

    public SpdySession(int sendWindowSize2, int receiveWindowSize2) {
        this.sendWindowSize = new AtomicInteger(sendWindowSize2);
        this.receiveWindowSize = new AtomicInteger(receiveWindowSize2);
    }

    /* access modifiers changed from: 0000 */
    public int numActiveStreams(boolean remote) {
        if (remote) {
            return this.activeRemoteStreams.get();
        }
        return this.activeLocalStreams.get();
    }

    /* access modifiers changed from: 0000 */
    public boolean noActiveStreams() {
        return this.activeStreams.isEmpty();
    }

    /* access modifiers changed from: 0000 */
    public boolean isActiveStream(int streamId) {
        return this.activeStreams.containsKey(Integer.valueOf(streamId));
    }

    /* access modifiers changed from: 0000 */
    public Set<Integer> getActiveStreams() {
        TreeSet<Integer> StreamIds = new TreeSet<>(new PriorityComparator());
        StreamIds.addAll(this.activeStreams.keySet());
        return StreamIds;
    }

    /* access modifiers changed from: 0000 */
    public void acceptStream(int streamId, byte priority, boolean remoteSideClosed, boolean localSideClosed, int sendWindowSize2, int receiveWindowSize2, boolean remote) {
        if ((remoteSideClosed && localSideClosed) || this.activeStreams.put(Integer.valueOf(streamId), new StreamState(priority, remoteSideClosed, localSideClosed, sendWindowSize2, receiveWindowSize2)) != null) {
            return;
        }
        if (remote) {
            this.activeRemoteStreams.incrementAndGet();
        } else {
            this.activeLocalStreams.incrementAndGet();
        }
    }

    private StreamState removeActiveStream(int streamId, boolean remote) {
        StreamState state = this.activeStreams.remove(Integer.valueOf(streamId));
        if (state != null) {
            if (remote) {
                this.activeRemoteStreams.decrementAndGet();
            } else {
                this.activeLocalStreams.decrementAndGet();
            }
        }
        return state;
    }

    /* access modifiers changed from: 0000 */
    public void removeStream(int streamId, boolean remote) {
        StreamState state = removeActiveStream(streamId, remote);
        if (state != null) {
            for (MessageEvent e = state.removePendingWrite(); e != null; e = state.removePendingWrite()) {
                e.getFuture().setFailure(STREAM_CLOSED);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isRemoteSideClosed(int streamId) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        return state == null || state.isRemoteSideClosed();
    }

    /* access modifiers changed from: 0000 */
    public void closeRemoteSide(int streamId, boolean remote) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            state.closeRemoteSide();
            if (state.isLocalSideClosed()) {
                removeActiveStream(streamId, remote);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean isLocalSideClosed(int streamId) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        return state == null || state.isLocalSideClosed();
    }

    /* access modifiers changed from: 0000 */
    public void closeLocalSide(int streamId, boolean remote) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            state.closeLocalSide();
            if (state.isRemoteSideClosed()) {
                removeActiveStream(streamId, remote);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean hasReceivedReply(int streamId) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        return state != null && state.hasReceivedReply();
    }

    /* access modifiers changed from: 0000 */
    public void receivedReply(int streamId) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            state.receivedReply();
        }
    }

    /* access modifiers changed from: 0000 */
    public int getSendWindowSize(int streamId) {
        if (streamId == 0) {
            return this.sendWindowSize.get();
        }
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            return state.getSendWindowSize();
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public int updateSendWindowSize(int streamId, int deltaWindowSize) {
        if (streamId == 0) {
            return this.sendWindowSize.addAndGet(deltaWindowSize);
        }
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            return state.updateSendWindowSize(deltaWindowSize);
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public int updateReceiveWindowSize(int streamId, int deltaWindowSize) {
        if (streamId == 0) {
            return this.receiveWindowSize.addAndGet(deltaWindowSize);
        }
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (deltaWindowSize > 0) {
            state.setReceiveWindowSizeLowerBound(0);
        }
        if (state != null) {
            return state.updateReceiveWindowSize(deltaWindowSize);
        }
        return -1;
    }

    /* access modifiers changed from: 0000 */
    public int getReceiveWindowSizeLowerBound(int streamId) {
        if (streamId == 0) {
            return 0;
        }
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            return state.getReceiveWindowSizeLowerBound();
        }
        return 0;
    }

    /* access modifiers changed from: 0000 */
    public void updateAllSendWindowSizes(int deltaWindowSize) {
        for (StreamState state : this.activeStreams.values()) {
            state.updateSendWindowSize(deltaWindowSize);
        }
    }

    /* access modifiers changed from: 0000 */
    public void updateAllReceiveWindowSizes(int deltaWindowSize) {
        for (StreamState state : this.activeStreams.values()) {
            state.updateReceiveWindowSize(deltaWindowSize);
            if (deltaWindowSize < 0) {
                state.setReceiveWindowSizeLowerBound(deltaWindowSize);
            }
        }
    }

    /* access modifiers changed from: 0000 */
    public boolean putPendingWrite(int streamId, MessageEvent evt) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        return state != null && state.putPendingWrite(evt);
    }

    /* access modifiers changed from: 0000 */
    public MessageEvent getPendingWrite(int streamId) {
        if (streamId == 0) {
            for (Integer id : getActiveStreams()) {
                StreamState state = this.activeStreams.get(id);
                if (state.getSendWindowSize() > 0) {
                    MessageEvent e = state.getPendingWrite();
                    if (e != null) {
                        return e;
                    }
                }
            }
            return null;
        }
        StreamState state2 = this.activeStreams.get(Integer.valueOf(streamId));
        if (state2 != null) {
            return state2.getPendingWrite();
        }
        return null;
    }

    /* access modifiers changed from: 0000 */
    public MessageEvent removePendingWrite(int streamId) {
        StreamState state = this.activeStreams.get(Integer.valueOf(streamId));
        if (state != null) {
            return state.removePendingWrite();
        }
        return null;
    }
}