package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;

public abstract class WebSocketFrame {
    private ChannelBuffer binaryData;
    private boolean finalFragment = true;
    private int rsv;

    public ChannelBuffer getBinaryData() {
        return this.binaryData;
    }

    public void setBinaryData(ChannelBuffer binaryData2) {
        this.binaryData = binaryData2;
    }

    public boolean isFinalFragment() {
        return this.finalFragment;
    }

    public void setFinalFragment(boolean finalFragment2) {
        this.finalFragment = finalFragment2;
    }

    public int getRsv() {
        return this.rsv;
    }

    public void setRsv(int rsv2) {
        this.rsv = rsv2;
    }
}