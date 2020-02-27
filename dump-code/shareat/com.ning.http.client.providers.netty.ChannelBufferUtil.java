package com.ning.http.client.providers.netty;

import org.jboss.netty.buffer.ChannelBuffer;

public class ChannelBufferUtil {
    public static byte[] channelBuffer2bytes(ChannelBuffer b) {
        int readable = b.readableBytes();
        int readerIndex = b.readerIndex();
        if (b.hasArray()) {
            byte[] array = b.array();
            if (b.arrayOffset() == 0 && readerIndex == 0 && array.length == readable) {
                return array;
            }
        }
        byte[] array2 = new byte[readable];
        b.getBytes(readerIndex, array2);
        return array2;
    }
}