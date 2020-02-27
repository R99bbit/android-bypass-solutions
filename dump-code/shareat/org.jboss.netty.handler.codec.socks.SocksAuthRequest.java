package org.jboss.netty.handler.codec.socks;

import com.ning.http.multipart.StringPart;
import java.nio.charset.CharsetEncoder;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.handler.codec.socks.SocksMessage.SubnegotiationVersion;
import org.jboss.netty.handler.codec.socks.SocksRequest.SocksRequestType;
import org.jboss.netty.util.CharsetUtil;

public final class SocksAuthRequest extends SocksRequest {
    private static final SubnegotiationVersion SUBNEGOTIATION_VERSION = SubnegotiationVersion.AUTH_PASSWORD;
    private static final CharsetEncoder asciiEncoder = CharsetUtil.getEncoder(CharsetUtil.US_ASCII);
    private final String password;
    private final String username;

    public SocksAuthRequest(String username2, String password2) {
        super(SocksRequestType.AUTH);
        if (username2 == null) {
            throw new NullPointerException("username");
        } else if (password2 == null) {
            throw new NullPointerException("username");
        } else if (!asciiEncoder.canEncode(username2) || !asciiEncoder.canEncode(password2)) {
            throw new IllegalArgumentException(" username: " + username2 + " or password: " + password2 + " values should be in pure ascii");
        } else if (username2.length() > 255) {
            throw new IllegalArgumentException(username2 + " exceeds 255 char limit");
        } else if (password2.length() > 255) {
            throw new IllegalArgumentException(password2 + " exceeds 255 char limit");
        } else {
            this.username = username2;
            this.password = password2;
        }
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public void encodeAsByteBuf(ChannelBuffer channelBuffer) throws Exception {
        channelBuffer.writeByte(SUBNEGOTIATION_VERSION.getByteValue());
        channelBuffer.writeByte(this.username.length());
        channelBuffer.writeBytes(this.username.getBytes(StringPart.DEFAULT_CHARSET));
        channelBuffer.writeByte(this.password.length());
        channelBuffer.writeBytes(this.password.getBytes(StringPart.DEFAULT_CHARSET));
    }
}