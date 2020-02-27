package org.jboss.netty.channel.socket.nio;

import java.nio.ByteBuffer;
import org.jboss.netty.util.ExternalResourceReleasable;
import org.jboss.netty.util.internal.ByteBufferUtil;

final class SocketReceiveBufferAllocator implements ExternalResourceReleasable {
    private ByteBuffer buf;
    private int exceedCount;
    private final int maxExceedCount;
    private final int percentual;

    SocketReceiveBufferAllocator() {
        this(16, 80);
    }

    SocketReceiveBufferAllocator(int maxExceedCount2, int percentual2) {
        this.maxExceedCount = maxExceedCount2;
        this.percentual = percentual2;
    }

    /* access modifiers changed from: 0000 */
    public ByteBuffer get(int size) {
        if (this.buf == null) {
            return newBuffer(size);
        }
        if (this.buf.capacity() < size) {
            return newBuffer(size);
        }
        if ((this.buf.capacity() * this.percentual) / 100 > size) {
            int i = this.exceedCount + 1;
            this.exceedCount = i;
            if (i == this.maxExceedCount) {
                return newBuffer(size);
            }
            this.buf.clear();
        } else {
            this.exceedCount = 0;
            this.buf.clear();
        }
        return this.buf;
    }

    private ByteBuffer newBuffer(int size) {
        if (this.buf != null) {
            this.exceedCount = 0;
            ByteBufferUtil.destroy(this.buf);
        }
        this.buf = ByteBuffer.allocateDirect(normalizeCapacity(size));
        return this.buf;
    }

    private static int normalizeCapacity(int capacity) {
        int q = capacity >>> 10;
        if ((capacity & 1023) != 0) {
            q++;
        }
        return q << 10;
    }

    public void releaseExternalResources() {
        if (this.buf != null) {
            ByteBufferUtil.destroy(this.buf);
        }
    }
}