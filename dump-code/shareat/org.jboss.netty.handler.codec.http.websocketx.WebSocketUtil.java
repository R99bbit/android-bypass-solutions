package org.jboss.netty.handler.codec.http.websocketx;

import io.fabric.sdk.android.services.common.CommonUtils;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.handler.codec.base64.Base64;
import org.jboss.netty.util.CharsetUtil;

final class WebSocketUtil {
    @Deprecated
    static byte[] md5(byte[] bytes) {
        try {
            return MessageDigest.getInstance(CommonUtils.MD5_INSTANCE).digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("MD5 not supported on this platform");
        }
    }

    static ChannelBuffer md5(ChannelBuffer buffer) {
        try {
            MessageDigest md = MessageDigest.getInstance(CommonUtils.MD5_INSTANCE);
            if (buffer.hasArray()) {
                md.update(buffer.array(), buffer.arrayOffset() + buffer.readerIndex(), buffer.readableBytes());
            } else {
                md.update(buffer.toByteBuffer());
            }
            return ChannelBuffers.wrappedBuffer(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("MD5 not supported on this platform");
        }
    }

    @Deprecated
    static byte[] sha1(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA1").digest(bytes);
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("SHA-1 not supported on this platform");
        }
    }

    static ChannelBuffer sha1(ChannelBuffer buffer) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            if (buffer.hasArray()) {
                md.update(buffer.array(), buffer.arrayOffset() + buffer.readerIndex(), buffer.readableBytes());
            } else {
                md.update(buffer.toByteBuffer());
            }
            return ChannelBuffers.wrappedBuffer(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new InternalError("SHA-1 not supported on this platform");
        }
    }

    @Deprecated
    static String base64(byte[] bytes) {
        return Base64.encode(ChannelBuffers.wrappedBuffer(bytes)).toString(CharsetUtil.UTF_8);
    }

    static String base64(ChannelBuffer buffer) {
        return Base64.encode(buffer).toString(CharsetUtil.UTF_8);
    }

    static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        for (int i = 0; i < size; i++) {
            bytes[i] = (byte) randomNumber(0, 255);
        }
        return bytes;
    }

    static int randomNumber(int min, int max) {
        return (int) ((Math.random() * ((double) max)) + ((double) min));
    }

    private WebSocketUtil() {
    }
}