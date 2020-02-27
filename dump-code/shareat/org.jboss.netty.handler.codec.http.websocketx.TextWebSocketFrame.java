package org.jboss.netty.handler.codec.http.websocketx;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.CharsetUtil;

public class TextWebSocketFrame extends WebSocketFrame {
    public TextWebSocketFrame() {
        setBinaryData(ChannelBuffers.EMPTY_BUFFER);
    }

    public TextWebSocketFrame(String text) {
        if (text == null || text.length() == 0) {
            setBinaryData(ChannelBuffers.EMPTY_BUFFER);
        } else {
            setBinaryData(ChannelBuffers.copiedBuffer((CharSequence) text, CharsetUtil.UTF_8));
        }
    }

    public TextWebSocketFrame(ChannelBuffer binaryData) {
        setBinaryData(binaryData);
    }

    public TextWebSocketFrame(boolean finalFragment, int rsv, String text) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        if (text == null || text.length() == 0) {
            setBinaryData(ChannelBuffers.EMPTY_BUFFER);
        } else {
            setBinaryData(ChannelBuffers.copiedBuffer((CharSequence) text, CharsetUtil.UTF_8));
        }
    }

    public TextWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        setBinaryData(binaryData);
    }

    public String getText() {
        if (getBinaryData() == null) {
            return null;
        }
        return getBinaryData().toString(CharsetUtil.UTF_8);
    }

    public void setText(String text) {
        if (text == null) {
            throw new NullPointerException("text");
        }
        setBinaryData(ChannelBuffers.copiedBuffer((CharSequence) text, CharsetUtil.UTF_8));
    }

    public String toString() {
        return getClass().getSimpleName() + "(text: " + getText() + ')';
    }
}