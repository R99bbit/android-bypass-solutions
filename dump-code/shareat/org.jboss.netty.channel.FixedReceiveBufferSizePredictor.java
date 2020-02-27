package org.jboss.netty.channel;

public class FixedReceiveBufferSizePredictor implements ReceiveBufferSizePredictor {
    private final int bufferSize;

    public FixedReceiveBufferSizePredictor(int bufferSize2) {
        if (bufferSize2 <= 0) {
            throw new IllegalArgumentException("bufferSize must greater than 0: " + bufferSize2);
        }
        this.bufferSize = bufferSize2;
    }

    public int nextReceiveBufferSize() {
        return this.bufferSize;
    }

    public void previousReceiveBufferSize(int previousReceiveBufferSize) {
    }
}