package org.jboss.netty.handler.codec.socks;

import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.handler.codec.replay.ReplayingDecoder;
import org.jboss.netty.handler.codec.socks.SocksMessage.AddressType;
import org.jboss.netty.handler.codec.socks.SocksMessage.CmdType;
import org.jboss.netty.handler.codec.socks.SocksMessage.ProtocolVersion;

public class SocksCmdRequestDecoder extends ReplayingDecoder<State> {
    private static final String name = "SOCKS_CMD_REQUEST_DECODER";
    private AddressType addressType;
    private CmdType cmdType;
    private int fieldLength;
    private String host;
    private SocksRequest msg = SocksCommonUtils.UNKNOWN_SOCKS_REQUEST;
    private int port;
    private byte reserved;
    private ProtocolVersion version;

    enum State {
        CHECK_PROTOCOL_VERSION,
        READ_CMD_HEADER,
        READ_CMD_ADDRESS
    }

    public static String getName() {
        return name;
    }

    public SocksCmdRequestDecoder() {
        super(State.CHECK_PROTOCOL_VERSION);
    }

    /* access modifiers changed from: protected */
    /* JADX WARNING: Code restructure failed: missing block: B:10:0x0057, code lost:
        r5.host = org.jboss.netty.handler.codec.socks.SocksCommonUtils.intToIp(r8.readInt());
        r5.port = r8.readUnsignedShort();
        r5.msg = new org.jboss.netty.handler.codec.socks.SocksCmdRequest(r5.cmdType, r5.addressType, r5.host, r5.port);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:11:0x0077, code lost:
        r5.fieldLength = r8.readByte();
        r5.host = r8.readBytes(r5.fieldLength).toString(org.jboss.netty.util.CharsetUtil.US_ASCII);
        r5.port = r8.readUnsignedShort();
        r5.msg = new org.jboss.netty.handler.codec.socks.SocksCmdRequest(r5.cmdType, r5.addressType, r5.host, r5.port);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:12:0x00a2, code lost:
        r5.host = org.jboss.netty.handler.codec.socks.SocksCommonUtils.ipv6toStr(r8.readBytes(16).array());
        r5.port = r8.readUnsignedShort();
        r5.msg = new org.jboss.netty.handler.codec.socks.SocksCmdRequest(r5.cmdType, r5.addressType, r5.host, r5.port);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:2:0x000b, code lost:
        r6.getPipeline().remove((org.jboss.netty.channel.ChannelHandler) r5);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:3:0x0014, code lost:
        return r5.msg;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:7:0x002a, code lost:
        r5.cmdType = org.jboss.netty.handler.codec.socks.SocksMessage.CmdType.fromByte(r8.readByte());
        r5.reserved = r8.readByte();
        r5.addressType = org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.fromByte(r8.readByte());
        checkpoint(org.jboss.netty.handler.codec.socks.SocksCmdRequestDecoder.State.READ_CMD_ADDRESS);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:9:0x0053, code lost:
        switch(r5.addressType) {
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.IPv4 :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x0057;
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.DOMAIN :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x0077;
            case org.jboss.netty.handler.codec.socks.SocksMessage.AddressType.IPv6 :org.jboss.netty.handler.codec.socks.SocksMessage$AddressType: goto L_0x00a2;
            default: goto L_0x0056;
        };
     */
    public Object decode(ChannelHandlerContext ctx, Channel channel, ChannelBuffer buffer, State state) throws Exception {
        switch (state) {
            case CHECK_PROTOCOL_VERSION:
                this.version = ProtocolVersion.fromByte(buffer.readByte());
                if (this.version == ProtocolVersion.SOCKS5) {
                    checkpoint(State.READ_CMD_HEADER);
                    break;
                }
                break;
            case READ_CMD_HEADER:
                break;
            case READ_CMD_ADDRESS:
                break;
        }
    }
}