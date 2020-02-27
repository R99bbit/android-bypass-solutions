package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.CharsetUtil;

public class ContinuationWebSocketFrame extends WebSocketFrame {
    private String aggregatedText;

    public ContinuationWebSocketFrame() {
        setBinaryData(ChannelBuffers.EMPTY_BUFFER);
    }

    public ContinuationWebSocketFrame(ChannelBuffer binaryData) {
        setBinaryData(binaryData);
    }

    public ContinuationWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setBinaryData(binaryData);
    }

    public ContinuationWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData, String aggregatedText2) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setBinaryData(binaryData);
        this.aggregatedText = aggregatedText2;
    }

    public ContinuationWebSocketFrame(boolean finalFragment, int rsv, String text) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setText(text);
    }

    public String getText() {
        if (getBinaryData() == null) {
            return null;
        }
        return getBinaryData().toString(CharsetUtil.UTF_8);
    }

    public void setText(String text) {
        if (text == null || text.length() == 0) {
            setBinaryData(ChannelBuffers.EMPTY_BUFFER);
        } else {
            setBinaryData(ChannelBuffers.copiedBuffer((CharSequence) text, CharsetUtil.UTF_8));
        }
    }

    public String toString() {
        return getClass().getSimpleName() + "(data: " + getBinaryData() + ')';
    }

    public String getAggregatedText() {
        return this.aggregatedText;
    }

    public void setAggregatedText(String aggregatedText2) {
        this.aggregatedText = aggregatedText2;
    }
}