package org.jboss.netty.handler.ssl;

import java.nio.ByteBuffer;

public class SslBufferPool {
    private static final int DEFAULT_POOL_SIZE = 19162112;
    private static final int MAX_PACKET_SIZE = 18713;
    private int index;
    private final int maxBufferCount;
    private final ByteBuffer[] pool;

    public SslBufferPool() {
        this(DEFAULT_POOL_SIZE);
    }

    public SslBufferPool(int maxPoolSize) {
        if (maxPoolSize <= 0) {
            throw new IllegalArgumentException("maxPoolSize: " + maxPoolSize);
        }
        int maxBufferCount2 = maxPoolSize % MAX_PACKET_SIZE != 0 ? (maxPoolSize / MAX_PACKET_SIZE) + 1 : maxPoolSize / MAX_PACKET_SIZE;
        this.pool = new ByteBuffer[maxBufferCount2];
        this.maxBufferCount = maxBufferCount2;
    }

    public int getMaxPoolSize() {
        return this.maxBufferCount * MAX_PACKET_SIZE;
    }

    public synchronized int getUnacquiredPoolSize() {
        return this.index * MAX_PACKET_SIZE;
    }

    public synchronized ByteBuffer acquireBuffer() {
        ByteBuffer byteBuffer;
        if (this.index == 0) {
            byteBuffer = ByteBuffer.allocate(MAX_PACKET_SIZE);
        } else {
            ByteBuffer[] byteBufferArr = this.pool;
            int i = this.index - 1;
            this.index = i;
            byteBuffer = (ByteBuffer) byteBufferArr[i].clear();
        }
        return byteBuffer;
    }

    /* access modifiers changed from: 0000 */
    @Deprecated
    public ByteBuffer acquire() {
        return acquireBuffer();
    }

    public synchronized void releaseBuffer(ByteBuffer buffer) {
        if (this.index < this.maxBufferCount) {
            ByteBuffer[] byteBufferArr = this.pool;
            int i = this.index;
            this.index = i + 1;
            byteBufferArr[i] = buffer;
        }
    }

    /* access modifiers changed from: 0000 */
    @Deprecated
    public void release(ByteBuffer buffer) {
        releaseBuffer(buffer);
    }
}