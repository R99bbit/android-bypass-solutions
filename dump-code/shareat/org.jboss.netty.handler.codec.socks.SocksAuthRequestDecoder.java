package org.jboss.netty.handler.codec.socks;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.socks.SocksMessage.SubnegotiationVersion;

public class SocksAuthRequestDecoder extends ReplayingDecoder<State> {
    private static final String name = "SOCKS_AUTH_REQUEST_DECODER";
    private int fieldLength;
    private SocksRequest msg = SocksCommonUtils.UNKNOWN_SOCKS_REQUEST;
    private String password;
    private String username;
    private SubnegotiationVersion version;

    enum State {
        CHECK_PROTOCOL_VERSION,
        READ_USERNAME,
        READ_PASSWORD
    }

    public static String getName() {
        return name;
    }

    public SocksAuthRequestDecoder() {
        super(State.CHECK_PROTOCOL_VERSION);
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:2:0x000b, code lost:
        r4.getPipeline().remove((org.jboss.netty.channel.ChannelHandler) r3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:3:0x0014, code lost:
        return r3.msg;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x002a, code lost:
        r3.fieldLength = r6.readByte();
        r3.username = r6.readBytes(r3.fieldLength).toString(org.jboss.netty.util.CharsetUtil.US_ASCII);
        checkpoint(org.jboss.netty.handler.codec.socks.SocksAuthRequestDecoder.State.READ_PASSWORD);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:8:0x0043, code lost:
        r3.fieldLength = r6.readByte();
        r3.password = r6.readBytes(r3.fieldLength).toString(org.jboss.netty.util.CharsetUtil.US_ASCII);
        r3.msg = new org.jboss.netty.handler.codec.socks.SocksAuthRequest(r3.username, r3.password);
     */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, State state) throws Exception {
        switch (state) {
            case CHECK_PROTOCOL_VERSION:
                this.version = SubnegotiationVersion.fromByte(buffer.readByte());
                if (this.version == SubnegotiationVersion.AUTH_PASSWORD) {
                    checkpoint(State.READ_USERNAME);
                    break;
                }
                break;
            case READ_USERNAME:
                break;
            case READ_PASSWORD:
                break;
        }
    }
}