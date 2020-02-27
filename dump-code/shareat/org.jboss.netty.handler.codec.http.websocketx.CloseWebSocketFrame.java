package org.jboss.netty.handler.codec.http.websocketx;

import java.io.UnsupportedEncodingException;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.util.CharsetUtil;

public class CloseWebSocketFrame extends WebSocketFrame {
    public CloseWebSocketFrame() {
        setBinaryData(ChannelBuffers.EMPTY_BUFFER);
    }

    public CloseWebSocketFrame(int statusCode, String reasonText) {
        this(true, 0, statusCode, reasonText);
    }

    public CloseWebSocketFrame(boolean finalFragment, int rsv) {
        this(finalFragment, rsv, null);
    }

    public CloseWebSocketFrame(boolean finalFragment, int rsv, int statusCode, String reasonText) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        byte[] reasonBytes = new byte[0];
        if (reasonText != null) {
            try {
                reasonBytes = reasonText.getBytes("UTF-8");
            } catch (UnsupportedEncodingException e) {
                reasonBytes = reasonText.getBytes();
            }
        }
        ChannelBuffer binaryData = ChannelBuffers.buffer(reasonBytes.length + 2);
        binaryData.writeShort(statusCode);
        if (reasonBytes.length > 0) {
            binaryData.writeBytes(reasonBytes);
        }
        binaryData.readerIndex(0);
        setBinaryData(binaryData);
    }

    public CloseWebSocketFrame(boolean finalFragment, int rsv, ChannelBuffer binaryData) {
        setFinalFragment(finalFragment);
        setRsv(rsv);
        if (binaryData == null) {
            setBinaryData(ChannelBuffers.EMPTY_BUFFER);
        } else {
            setBinaryData(binaryData);
        }
    }

    public int getStatusCode() {
        ChannelBuffer binaryData = getBinaryData();
        if (binaryData == null || binaryData.capacity() == 0) {
            return -1;
        }
        binaryData.readerIndex(0);
        short readShort = binaryData.readShort();
        binaryData.readerIndex(0);
        return readShort;
    }

    public String getReasonText() {
        ChannelBuffer binaryData = getBinaryData();
        if (binaryData == null || binaryData.capacity() <= 2) {
            return "";
        }
        binaryData.readerIndex(2);
        String channelBuffer = binaryData.toString(CharsetUtil.UTF_8);
        binaryData.readerIndex(0);
        return channelBuffer;
    }

    public String toString() {
        return getClass().getSimpleName();
    }
}