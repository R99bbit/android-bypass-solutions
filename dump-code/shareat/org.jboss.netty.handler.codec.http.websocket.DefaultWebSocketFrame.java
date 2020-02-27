package org.jboss.netty.handler.codec.http.websocket;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.CharsetUtil;

@Deprecated
public class DefaultWebSocketFrame implements WebSocketFrame {
    private ChannelBuffer binaryData;
    private int type;

    public DefaultWebSocketFrame() {
        this(0, ChannelBuffers.EMPTY_BUFFER);
    }

    public DefaultWebSocketFrame(String textData) {
        this(0, ChannelBuffers.copiedBuffer((CharSequence) textData, CharsetUtil.UTF_8));
    }

    public DefaultWebSocketFrame(int type2, ChannelBuffer binaryData2) {
        setData(type2, binaryData2);
    }

    public int getType() {
        return this.type;
    }

    public boolean isText() {
        return (getType() & 128) == 0;
    }

    public boolean isBinary() {
        return !isText();
    }

    public ChannelBuffer getBinaryData() {
        return this.binaryData;
    }

    public String getTextData() {
        return getBinaryData().toString(CharsetUtil.UTF_8);
    }

    public void setData(int type2, ChannelBuffer binaryData2) {
        if (binaryData2 == null) {
            throw new NullPointerException("binaryData");
        } else if ((type2 & 128) != 0 || binaryData2.indexOf(binaryData2.readerIndex(), binaryData2.writerIndex(), -1) < 0) {
            this.type = type2 & 255;
            this.binaryData = binaryData2;
        } else {
            throw new IllegalArgumentException("a text frame should not contain 0xFF.");
        }
    }

    public String toString() {
        return getClass().getSimpleName() + "(type: " + getType() + ", " + "data: " + getBinaryData() + ')';
    }
}